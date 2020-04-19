var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var autoIncrement = require('mongoose-easy-auto-increment');


var UserSchema = new Schema({
  idUser: {
    type: Number,
    validate: {
      validator: Number.isInteger,
      message: '{VALUE} is not an integer value'
    }
  },
  username: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true
  },
  password: {
    type: String,
    required: true
  },
  agreeToBeNotified: {
    type: Boolean,
    default: false
  },
  encryptedUserId: {
    type: String,
    required: true
  }, 
  userType: {
    type: Number, //0= internal JWT, 1= Google
    default: 0,
    validate: {
      validator: Number.isInteger,
      message: '{VALUE} is not an integer value'
    }
  },
  createdAt: {
    type: Date,
    default: Date.now()
  }
});

UserSchema.plugin(autoIncrement, { field: 'idUser', collection: 'counters' });
var UserModel = mongoose.model('user', UserSchema);
module.exports = UserModel;
