var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var autoIncrement = require('mongoose-easy-auto-increment');

var ReportSchema = new Schema({
  idReport: {
    type: Number,
    validate: {
      validator: Number.isInteger,
      message: '{VALUE} is not an integer value'
    }
  },
  idUser: {
    type: String,
    required: true
  },
  testDate: {
    type: Date,
    requered: true
  },
  testResult: {
    type: Number,  //0 = not tested, no symptons, 1 positive, 2 high risk symptoms 
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now()
  }
});

ReportSchema.plugin(autoIncrement, { field: 'idReport', collection: 'counters' });
var ReportModel = mongoose.model('report', ReportSchema);
module.exports = ReportModel;
