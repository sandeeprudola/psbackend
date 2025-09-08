const express=require('express')
const router=express.Router();
const auth=require("../middlewares/adminAuth")
const zod=require('zod')

const adminSchema=zod.object({
    username:zod.string(),
    password:zod.string(),
    firstName:zod.string(),
    lastName:zod.string(),
    email:zod.string(),
    role:zod.string(),
    caninvite:zod.string()
})

router.post("/signup",)


module.exports=router;