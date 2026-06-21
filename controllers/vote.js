const User = require('../models/user')
const Candidate = require('../models/candidate')
const jwt = require('jsonwebtoken')
const nodemailer = require('nodemailer')

function getToken(req) {
    const authHeader = req.headers.authorization || req.headers.Authorization
    if (!authHeader) return null
    return authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : authHeader
}

function verifyToken(token) {
    try {
        return jwt.verify(token, process.env.JWT_SECRET)
    } catch (err) {
        return null
    }
}

async function authenticate(req, res) {
    const token = getToken(req)
    if (!token) {
        res.status(401).json({ message: 'No token provided' })
        return null
    }

    const decoded = verifyToken(token)
    if (!decoded) {
        res.status(401).json({ message: 'Invalid token' })
        return null
    }

    const user = await User.findOne({ _id: decoded.id })
    if (!user) {
        res.status(404).json({ message: 'User does not exist' })
        return null
    }

    return user
}

const generateOtp = async (req, res) => {
    try {
        const user = await authenticate(req, res)
        if (!user) return

        const votingOtp = Math.floor(100000 + Math.random() * 900000).toString()
        const votingOtpExpires = Date.now() + 3600000
        user.votingOtp = votingOtp
        user.votingOtpExpires = votingOtpExpires
        await user.save()

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            secure: true,
            auth: {
                user: process.env.EMAIL,
                pass: process.env.PASSWORD
            }
        })

        const mailOptions = {
            from: process.env.EMAIL,
            to: user.email,
            subject: 'Voting OTP',
            html: `<p>Hi ${user.name},</p><p><strong>Your voting OTP is ${votingOtp}</strong></p>`
        }

        transporter.sendMail(mailOptions, (err, info) => {
            if (err) {
                console.log(err)
                return res.status(500).json({ message: err.message })
            }
            console.log(info)
            res.status(200).json({ message: 'OTP sent successfully' })
        })
    } catch (error) {
        console.log(error)
        res.status(500).json({ message: error.message })
    }
}

const verifyVotingOtp = async (req, res) => {
    try {
        const user = await authenticate(req, res)
        if (!user) return

        if (user.votingOtp != req.body.otp) return res.status(400).json({ message: 'Invalid OTP' })
        if (user.votingOtpExpires < Date.now()) return res.status(400).json({ message: 'OTP has expired' })

        user.votingOtp = null
        user.votingOtpExpires = null
        user.isAccredited = true
        await user.save()

        const newToken = jwt.sign({ id: user._id, matric: user.matric, voted: user.voted, department: user.department, level: user.level, isVerified: user.isVerified, role: user.role, isAccredited: user.isAccredited }, process.env.JWT_SECRET, { expiresIn: '1h' })
        res.status(200).json({ message: 'OTP verified successfully', token: newToken })
    } catch (error) {
        console.log(error)
        res.status(500).json({ message: error.message })
    }
}

const getCandidates = async (req, res) => {
    try {
        const user = await authenticate(req, res)
        if (!user) return

        if (!user.isAccredited) return res.status(400).json({ message: 'User is not accredited' })
        if (user.hasVoted) return res.status(400).json({ message: 'User has already voted' })

        const candidates = await Candidate.find({ post: { $ne: 'SRC' } })
        const src = await Candidate.find({ post: 'SRC', department: { $eq: user.department } })
        res.status(200).json({ candidates, src })
    } catch (error) {
        console.log(error)
        res.status(500).json({ message: error.message })
    }
}

const vote = async (req, res) => {
    try {
        const user = await authenticate(req, res)
        if (!user) return

        const { ballot } = req.body
        if (!ballot) return res.status(400).json({ message: 'Ballot is required' })

        if (!user.isAccredited) return res.status(400).json({ message: 'User is not accredited' })
        if (user.hasVoted) return res.status(400).json({ message: 'User has already voted' })

        const president = await Candidate.findOne({ _id: ballot.president })
        if (president) {
            president.votes += 1
            await president.save()
        }
        const vicePresident = await Candidate.findOne({ _id: ballot['vice president'] })
        if (vicePresident) {
            vicePresident.votes += 1
            await vicePresident.save()
        }
        const genSec = await Candidate.findOne({ _id: ballot['general secretary'] })
        if (genSec) {
            genSec.votes += 1
            await genSec.save()
        }
        const sportSec = await Candidate.findOne({ _id: ballot['sports secretary'] })
        if (sportSec) {
            sportSec.votes += 1
            await sportSec.save()
        }

        user.hasVoted = true
        await user.save()
        res.status(200).json({ message: 'Voting successful' })
    } catch (error) {
        console.log(error)
        res.status(500).json({ message: error.message })
    }
}

module.exports = { generateOtp, verifyVotingOtp, vote, getCandidates }

