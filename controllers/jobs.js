const Job = require('../models/Job')
const {StatusCodes} = require('http-status-codes')
const {BadRequestError, NotFoundError} = require('../errors')

const getAllJobs = async (req,res) => {
    
    const jobs = await Job.find({createdBy:req.user.userId}).sort('createdAt')

    /* console.log(jobs); */

    res.status(StatusCodes.OK).json({jobs,count:jobs.length})
}

const getJob = async (req,res) => {

    const {user:{userId},params:{id:jobId}} = req
    
    const job = await Job.findOne({
        _id:jobId, createdBy:userId
    })

    if(!job)
    {
        throw new NotFoundError(`No Job Id ${jobId}`)
    }

    res.status(StatusCodes.OK).json({job})
}

const createJob = async (req,res) => {

    /* console.log(req.user.userId)
    res.send('create jobs') */

    req.body.createdBy = req.user.userId
    const job = await Job.create(req.body)
    res.status(StatusCodes.CREATED).json(req.body)
}

const updateJob = async (req,res) => {
    
    const {user:{userId},params:{id:jobId},body:{company,position}} = req
    
    if(company === "" || position === "")
    {
        throw new BadRequestError("Company and Position are mandatory")
    }

    const job = await Job.findOneAndUpdate({_id:jobId, createdBy:userId}, req.body, {new:true, runValidators:true})

    if(!job)
    {
        throw new NotFoundError(`No Job Id ${jobId}`)
    }

    res.status(StatusCodes.OK).json({job})
}

const deleteJob = async (req,res) => {
    
    const {user:{userId},params:{id:jobId}} = req

    const job = await Job.findOneAndRemove({_id:jobId, createdBy:userId})

    if(!job)
    {
        throw new NotFoundError(`No Job Id ${jobId}`)
    }

    res.status(StatusCodes.OK).json({job})
}

module.exports = {
    getAllJobs,
    getJob,
    createJob,
    updateJob,
    deleteJob,
}