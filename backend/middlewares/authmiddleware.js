const { JWT_SECRET } = require("../config");
const jwt=require('jsonwebtoken')


function authmiddleware(req,res,next){
    const authHeader=req.headers.authorization;
    if(!authHeader || !authHeader.startsWith("Bearer ")){
        return res.status(411).json({
            msg:"no token provided"
        })
    }

    const token= authHeader.split(" ")[1];

    try{
        const decoded = jwt.verify(token,JWT_SECRET);

        req.user={
            id:decoded.userId,
            role:decoded.role,
        }
        if(role.length && !role.includes(req.user.role)){
            return res.status(403).json({
                msg:"Forbidden: insufficient role"
            })
        }
        next();
    }
    catch(err){
        return res.status(401).json({
            msg:"invaild or expired token"
        })
    }
}
module.exports=authmiddleware


