import express from "express";
import dotenv from "dotenv";
import mongoose from "mongoose";
import { userRouter } from "./Routes/UserRoute.js"; // Assuming correct path to UserRoute.js
import cors from "cors";
import cookieParser from "cookie-parser";
dotenv.config();

const app = express();

app.use(express.json());
app.use(cors({
    origin: 'http://localhost:5173', 
    credentials: true,
  }));
  
app.use('/auth', userRouter); // Mount userRouter at /auth
app.use(cookieParser())

mongoose.connect(process.env.MONGO_URI, {
 
}).then(() => {
  console.log("DB Connected");
}).catch(err => {
  console.error("DB Connection Error: ", err);
  process.exit(1); // Exit the process if unable to connect to the DB
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
