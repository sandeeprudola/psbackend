const express=require('express')
const Admin=require("../models/Admin")
const router=express.Router();
const auth=require("../middlewares/adminAuth")
const zod=require('zod')
const bcrypt=require('bcryptjs');
const { JWT_SECRET } = require('../config');
const jwt=require('jsonwebtoken')

const adminSchema=zod.object({
    username:zod.string(),
    password:zod.string(),
    firstName:zod.string(),
    lastName:zod.string(),
    email:zod.string(),
    role: zod.string().optional(),
    caninvite: zod.boolean().optional()
})

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


module.exports=router;