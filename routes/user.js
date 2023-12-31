const express = require('express');
const router = express.Router();

const {register, login, forgotPassword, resetPassword, verify, resendOTP, update, registerA, checkABE } = require('../controllers/userAuth')
const {generateOtp, verifyVotingOtp, vote, getCandidates} = require('../controllers/vote')

router.post('/register', register)
router.post('/login', login)
router.post('/verify', verify)
router.post('/resend-otp', resendOTP)
router.post('/forgot-password', forgotPassword)
router.post('/reset-password', resetPassword)
router.post('/generate-voting-otp', generateOtp)
router.post('/verify-voting-otp', verifyVotingOtp)
router.get('/candidates', getCandidates)
router.post('/vote', vote)
router.post('/update', update)
router.post('/reg', registerA)
router.post('/abe', checkABE)

module.exports = router;