const express=require('express')
const userRouter=require("./user")
const employeeRouter=require("./employee")
const adminRouter=require("./admin");

const router=express.Router();

router.use("/user",userRouter)
router.use("/admin",adminRouter)
router.use("/employee",employeeRouter)

module.exports=router;