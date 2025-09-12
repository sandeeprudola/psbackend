const {JWT_SECRET}=require("../config")
const jwt=require('jsonwebtoken');
const Admin = require("../models/Admin");

const adminAuth = async (req, res, next) => {
    const admincount=await Admin.countDocuments();
    if(admincount<=2){
        return next();
    }
    const authHeader=req.headers.authorization
    if(!authHeader || !authHeader.startsWith("Bearer ")){
        return res.status(411).json({
            msg:"invalid credentials"
        })
    }

    try{
    const token=authHeader.split(" ")[1];
    const decoded=jwt.verify(token,JWT_SECRET)

    const admin=await Admin.findById(decoded.id)
    if(!admin){
        return res.status(401).json({
            msg:"no admin found"
        })
    }
    req.admin=admin;
    next();
    }

    catch(err){
        return res.status(411).json({
            msg:"there is some problem in your try code"
        })
    }
  };

  module.exports=adminAuth;
  