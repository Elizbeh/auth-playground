export const getProfile = (req, res) => {
    res.status(200).json({email: req.userEmail})
}