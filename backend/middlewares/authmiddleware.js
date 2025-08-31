const { JWT_SECRET } = require("../config");
const jwt=require('jsonwebtoken')


function authmiddleware(req,res,next){
    const authHeaders=req.headers.authorization;

    if(!authHeaders || !authHeaders.startsWith('Bearer ')){
        return res.status(400).json({msg:"there is some error in token"})
    }
    const token=authHeaders.split(' ')[1];
    try{
        const decoded=jwt.verify(token,JWT_SECRET);
        req.user_id=decoded.userId;
        next();
    }
    catch(err){
        return res.status(400).json({err:"there is some error"})
    }

}
module.exports=authmiddleware


