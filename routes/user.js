const express = require('express');
const router = express.Router();

const { login, update } = require('../controllers/userAuth')
const { generateOtp, verifyVotingOtp, vote, getCandidates } = require('../controllers/vote')

router.post('/login', login)
router.post('/generate-voting-otp', generateOtp)
router.post('/verify-voting-otp', verifyVotingOtp)
router.get('/candidates', getCandidates)
router.post('/vote', vote)
router.post('/update', update)

module.exports = router;