// Importing "dotenv" package to read ".env" file holding environment variables
require("dotenv").config()

// Importing "mongodb" package to have MongoDB connections
const mongodb = require("mongodb")

// Reading environment variables from ".env" file
const userID = process.env.USER_ID
const password = process.env.PASSWORD

// const MongoClient = mongodb.MongoClient

const uriMongoDB = `mongodb+srv://${userID}:${password}@cluster0.v60qg.mongodb.net/?retryWrites=true&w=majority`

let database

async function connect() {
    const client = await mongodb.MongoClient.connect(uriMongoDB)
    database = client.db("auth-demo")
}

function getDB() {
    if (!database) {
        throw { message: "Database connection not established" }
    }
    return database
}

module.exports = {
    connectToDatabase: connect,
    getDb: getDB
}