const mongoose = require('mongoose')

const candidateSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        min: 3,
        max: 255
    },
    otherName: {
        type: String,
    },
    photo: {
        type: String,
        required: true,
    },
    nickname: {
        type: String,
        required: true,
    },
    post: {
        type: String,
        required: true,
        enum: ['President', 'Vice President', 'General Secretary', 'Financial Secretary', 'Welfare Secretary', 'Treasurer', 'Social Secretary', 'Assistant General Secretary', 'PRO', 'Sports Secretary', 'Technical Director', 'SRC', 'Librarian'],
    },
    department: {
        type: String,
        required: true,
        enum: ['ABE', 'BME', 'CHE', 'CPE', 'CVE', 'ELE', 'FBE', 'MEE', 'MME', 'WRE']
    },
    level: {
        type: String,
        required: false,
        enum: ['100', '200', '300', '400']
    },
    voters: [{
        type: String,
    }],
    votes: {
        type: Number,
        default: 0,
    },
}, { timestamps: true })

const Candidate = mongoose.model('Candidate', candidateSchema)

module.exports = Candidate