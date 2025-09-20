const express=require('express')
const Admin=require("../models/Admin")
const User=require("../models/User")
const Emp=require("../models/Emp")
const Appointment=require("../models/Appointment")
const router=express.Router();
const auth=require("../middlewares/adminAuth")
const zod=require('zod')
const bcrypt=require('bcryptjs');
const { JWT_SECRET } = require('../config');
const jwt=require('jsonwebtoken');
const adminAuth = require('../middlewares/adminAuth');
const { date } = require('zod/mini')
const { parse } = require('dotenv')

const adminSchema=zod.object({
    username:zod.string(),
    password:zod.string(),
    firstName:zod.string(),
    lastName:zod.string(),
    email:zod.string(),
    role: zod.string().optional(),
    caninvite: zod.boolean().optional()
})

function parsePagination(req){
    const page=Math.max(parseInt(req.query.page || "1",10),1);
    const limit=Math.min(Math.max(parseInt(req.query.limit || "4",10),1),100)
    return {page,limit,skip:(page-1)*limit};
}
function parseDateRange(req){
    const from= req.query.from ? new Date(req.query.from):undefined;
    const to=req.query.to ? new Date(req.query.to):undefined;
    if(to)to.setHours(23,59,59,999);
    return {from,to};
}

router.post("/signup",auth,async(req,res)=>{
    try{
        const {username,password,firstName,lastName,email,role,caninvite}=req.body;
        const countSuperAdmin=await Admin.countDocuments();

        if(role=="super-admin"){
            if(countSuperAdmin>=2){
                return res.status(411).json({
                    msg:"only 2 superadmins are allowed"
                })
            }
        }

        const hashedPassword=await bcrypt.hash(password,10);
        const newAdmin=new Admin({
            username,
            password:hashedPassword,
            firstName,
            lastName,
            email,
            role:"super-admin",
            caninvite:true
        })
        await newAdmin.save()
        const token=jwt.sign({id:newAdmin._id,role:"super-admin"},JWT_SECRET,
            {expiresIn:"1d"}
        )
        res.status(200).json({
            msg:"super-admin created successfully",
            token
        })

        if(role==admin){
            const authHeader=req.headers.authorization
            if(!authHeader || !authHeader.startsWith("Bearer ")){
                return res.status(401).json({
                    msg:"super-Login required to create admins"
                })
            }
            const token=authHeader.split(" ")[1];
            const decoded=jwt.verify(token,JWT_SECRET);

            const creator=await Admin.findById(decoded.id);
            if(!creator || creator.role!=="super-admin"){
                res.status(401).json({
                    msg:"only super-admins can create admins"
                })
            }
            const hashedPassword=await bcrypt.hash(password,10);
            const newAdmin=new Admin({
                username,
                password:hashedPassword,
                firstName,
                lastName,
                email,
                role:"admin",
            })
            await newAdmin.save();

            res.status(200).json({
                msg:"admin created successfully",
                token
            })
        }
        res.status(400).json({
            msg:"role is wrong"
        })
    }
    catch(err){
        res.status(500).json({ msg: "Server error", error: err.message });
    }
})

const adminSigninSchema=zod.object({
    username:zod.string(),
    password:zod.string(),
 })

router.post("/signin",async(req,res)=>{
    try{
        const body=req.body
        const {success}=adminSigninSchema.safeParse(body)

        if(!success){
            return res.status(401).json({
                msg:"admin not found"
            })
        }
        const admin=await Admin.findOne({
            username:body.username
        })

        if(admin){
            const isvalid=await bcrypt.compare(body.password,admin.password)
            if(!isvalid){
                res.status(401).json({
                    msg:"wrong credentials"
                })
            }
            const token= jwt.sign({
                userid:admin._id,
                role:admin.role
            },JWT_SECRET)

            res.status(200).json({
                msg:"signin success",
                token
            })
        }
    }
    catch(err){
            res.status(500).json({
                msg:"error in try code"
            })
    }

})

//dashboard and analytics route 

router.get("/dashboard",adminAuth,async(req,res)=>{
    try{    
        const [totalUsers,totalEmp,totalAdmins,totalAppointments]=await Promise.all([
            User.countDocuments(),
            Emp.countDocuments(),
            Appointment.countDocuments(),
            Admin.countDocuments(),


    ])
    const startOfToday=new Date();
    startOfToday.setHours(0,0,0,0);
    const endOfToday=new Date();
    endOfToday.setHours(23,59,59,999);

    const [todayAppointments,pendingPayments,scheduledToday]=await Promise.all([
        Appointment.countDocuments({
            appointmentdate:{$gte:startOfToday,$lte:endOfToday}
        }),
        Appointment.countDocuments({paymentStatus:"pending"}),
        Appointment.find({
            appointmentdate:{$gte:startOfToday,$lte:endOfToday}
        }).select("patient staff appointmentdate status").populate("patient","firstName lastName ").populate("staff","firstName lastName specialization")
    ])

    return res.json({
        summary:{
            totalUsers,
            totalEmp,
            totalAdmins,
            totalAppointments,
            todayAppointments,
            pendingPayments
        },
        todaySchedule: scheduledToday
    });
    }
    catch(err){
        res.status(500).json({
            msg:"failed to load dashboard"
        })
    }
})

//stats from preferred date 
router.get("/stats", auth, async (req, res) => {
	try {
		

		const from = req.query.from ? new Date(req.query.from) : new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
		const to = req.query.to ? new Date(req.query.to) : new Date();
		to.setHours(23,59,59,999);

		// Status breakdown
		const statusAgg = await Appointment.aggregate([
			{ $match: { appointmentdate: { $gte: from, $lte: to } } },
			{ $group: { _id: "$status", count: { $sum: 1 } } },
			{ $project: { _id: 0, status: "$_id", count: 1 } }
		]);

		// Type breakdown
		const typeAgg = await Appointment.aggregate([
			{ $match: { appointmentdate: { $gte: from, $lte: to } } },
			{ $group: { _id: "$appointmentType", count: { $sum: 1 } } },
			{ $project: { _id: 0, type: "$_id", count: 1 } }
		]);

		// Daily counts
		const dailyAgg = await Appointment.aggregate([
            { $match: { appointmentdate: { $gte: from, $lte: to } } },
            {
                $group: {
                    _id: {
                        y: { $year: "$appointmentdate" },
                        m: { $month: "$appointmentdate" },
                        d: { $dayOfMonth: "$appointmentdate" }
                    },
                    count: { $sum: 1 }
                }
            },
            {
                $project: {
                    _id: 0,
                    date: { $dateFromParts: { year: "$_id.y", month: "$_id.m", day: "$_id.d" } },
                    count: 1
                }
            },
            { $sort: { date: 1 } }
        ]);

		// Top staff by appointment count
		const topStaffAgg = await Appointment.aggregate([
			{ $match: { appointmentdate: { $gte: from, $lte: to } } },
			{ $group: { _id: "$staff", count: { $sum: 1 } } },
			{ $sort: { count: -1 } },
			{ $limit: 5 }
		]);

		// Enrich top staff details
		const staffIds = topStaffAgg.map(s => s._id);
		const staffDocs = await Emp.find({ _id: { $in: staffIds } }).select("firstName lastName role specialization");
		const staffMap = new Map(staffDocs.map(s => [s._id.toString(), s]));
		const topStaff = topStaffAgg.map(s => ({
			staffId: s._id,
			name: staffMap.get(String(s._id)) ? `${staffMap.get(String(s._id)).firstName} ${staffMap.get(String(s._id)).lastName}` : "Unknown",
			role: staffMap.get(String(s._id))?.role,
			specialization: staffMap.get(String(s._id))?.specialization,
			count: s.count
		}));

		// Payment breakdown
		const paymentAgg = await Appointment.aggregate([
			{ $match: { appointmentdate: { $gte: from, $lte: to } } },
			{ $group: { _id: "$paymentStatus", count: { $sum: 1 } } },
			{ $project: { _id: 0, paymentStatus: "$_id", count: 1 } }
		]);

		return res.json({
			range: { from, to },
			status: statusAgg,
			types: typeAgg,
			daily: dailyAgg,
			topStaff,
			payments: paymentAgg
		});
	} catch (err) {
		return res.status(500).json({ msg: "Failed to load stats", error: err.message });
	}
});

//User Essential Routes->

//get all users 
router.get("/users",adminAuth,async(req,res)=>{
    try{
        const{page,limit,skip}=parsePagination(req);
        const {role,q}=req.query;

        const query={};
        if(role)query.role=role;
        if(q){
            query.$or=[
                {firstName:{$regex:q,$options:"i"}},
                {lastName:{$regex:q,$options:"i"}},
                {email:{$regex:q,$options:"i"}},
                {username:{$regex:q,$options:"i"}}
            ];
        }
        const [items,total]=await Promise.all([
            User.find(query).sort({createdAt:-1}).skip(skip).limit(limit).select("-password"),
            User.countDocuments(query)
        ]);
        res.json({page,limit,total,items})
    }
    catch(err){
        return res.status(500).json({
            msg:"failed to fetch users"
        })
    }
})

//update users by their id's as query params
router.put("/users/:id",adminAuth,async(req,res)=>{
    try{
        const allowed = (({firstName, lastName,role})=>({firstName, lastName,role}))(req.body || {});
        const updated=await User.findByIdAndUpdate(req.params.id,{$set:allowed},{new:true,runValidators:true}).select("-password");
        if(!updated){
            return res.status(411).json({
                msg:"user not found"
            })
        }
        res.json({
            msg:"user updated"
        })
    }
    catch(err){
        return res.status(500).json({
            msg:"failed to update user"
        })
    }
})

//Staff Management Routes->
router.get("/staff",adminAuth,async(req,res)=>{
    try{
        const {page,limit,skip}=parsePagination(req);
        const {role,active,q}=req.query;

        const query={};
        if(role)query.role=role;
        if(active=="true" || active=="false")query.isActive=active==="true";
        if(q){
            query.$or=[
                {firstName:{$regex:q,$options:"i"}},
                {lastName:{$regex:q,$options:"i"}},
                {email:{$regex:q,$options:"i"}},
                {username:{$regex:q,$options:"i"}},
                {specialization:{$regex:q,$options:"i"}}

            ]
        }
        const[items,total]=await Promise.all([
            Emp.find(query).sort({createdAt:-1}).skip(skip).limit(limit).select("-password"),
            Emp.countDocuments(query)
        ])
        res.json({page,limit,total,items});
    }
        catch(err){
        res.status(500).json({msg:"Failed to fetch staff"});
    }
})

router.put("/staff/:id",adminAuth,async(req,res)=>{
    try{
        const allowed=(({firstName,lastName,phone, specialization,role,isActive})=>({firstName,lastName,phone,specialization,role,isActive}))(req.body ||{});
        const updated=await Emp.findByIdAndUpdate(req.params.id,{$set:allowed},{new:true},{runValidators:true}).select("-password")
        if(!updated)return res.status(411).json({msg:"staff not found"})
        res.json({
            msg:"staff updated"})    
    }
    catch(err){
        res.status(500).json({msg:"failed to update staff"})
    }
})

//Appointment Management Routes->

module.exports=router;