const User = require("./User");
const Emp = require("./Emp");

const mongoose = require('mongoose'); 
const { date, number, string, maxLength } = require("zod");

const AppointmentSchema = new mongoose.Schema({
   
    patient: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User', 
        required: true,
    },
    staff:{
        type:mongoose.Schema.Types.ObjectId,
        ref:'Emp',
        require:true,
    },
    appointmentdate:{
        type:date,
        require:true,
    },
    duration:{
        type:number,
        required:true,
        default:30,
    },
    status:{
        type: String,
        enum:['scheduled','confirmed','in-progress','completed','canceled'],
        default:'scheduled',
        required:true,
    },
    appointmentType:{
        type:String,
        required:true,
        enum:['consultation','speech-therapy','hearing-test','followup','emergency'],
    },
    notes:{
        type: String,
        trim: true,
        maxLength: 300,

    },
    createdAt:{
        type: Date,
        default:Date.now,
    },
    updatedAt:{
        type: Date,
        default:Date.now,
    },
    priority:{
        type:String,
        enum:['low','normal','high','emergency'],
        default:'normal',
    },
    paymentStatus:{
        type: String,
        enum:['pending','paid','partial','waived'],
        default:'pending',
    }


},);


module.exports = mongoose.model("Appointment", AppointmentSchema);

//hehehehe