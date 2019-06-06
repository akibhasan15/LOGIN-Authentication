const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')
// *!DEFINING YOUR SCHEMA
var UserSchema = new mongoose.Schema({
  email:{
    type: String,
    required: true,
    minlength: 4
  },
  username: {
    type: String,
    required: true,
    minlength: 4
  },
  password: {
    type: String,
    required: true
  },
  resetPasswordToken:{
    type:String
  },
  resetPasswordExpires:{
    type:String
  }

})

//*! WILL CHECK FOR PASSWORD CHANGE,EVERY TIME DATA SAVE
UserSchema.pre('save', function(next) {
  if (this.isModified('password')) {
    this.password = bcrypt.hashSync(this.password, 12)
  }
  next()
})

// *! CREATING A MODEL
var User = mongoose.model('User', UserSchema)

module.exports = { User }
