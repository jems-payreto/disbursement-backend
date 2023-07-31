require("dotenv").config();

const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const app = express();

const mysql = require("mysql2/promise");

app.use(
    cors({
        origin: (origin, callback) => {
            callback(null, true);
        },
        credentials: true,
    })
);
app.use(express.json());
app.use(cookieParser());

app.get("/", (req, res) => {
    return res.status(201).json({ name: "test", age: 12 });
});

// Refresh Token Handler
app.get("/refresh", async (req, res) => {
    console.log("pasok?");
    const connection = await mysql.createConnection({
        host: "localhost",
        user: "root",
        database: "disbursement",
    });

    const cookies = req.cookies;

    if (!cookies?.jwt) return res.sendStatus(401);

    console.log("inde 401");

    const refreshToken = cookies.jwt;
    res.clearCookie("jwt", { httpOnly: true, sameSite: "None", secure: true });

    const [rows] = await connection.execute(
        "SELECT * FROM users WHERE refreshToken = ?",
        [refreshToken]
    );

    // Detected refresh token reuse!
    if (rows.length === 0) {
        jwt.verify(
            refreshToken,
            process.env.REFRESH_TOKEN_SECRET,
            async (err, decoded) => {
                if (err) return res.sendStatus(403); //Forbidden
                // Delete refresh tokens of hacked user
                const [rows, fields] = await connection.execute(
                    "UPDATE users SET refreshToken = null WHERE email = ?",
                    [decoded.email],
                    [refreshToken]
                );
            }
        );
        return res.sendStatus(403); //Forbidden
    }

    jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET,
        async (err, decoded) => {
            console.log("decoded", decoded);
            console.log("err", err);
            // if (err) {
            //     // expired refresh token
            //     foundUser.refreshToken = [...newRefreshTokenArray];
            //     const result = await foundUser.save();
            // }
            // if (err || foundUser.username !== decoded.username)
            //     return res.sendStatus(403);

            // Refresh token was still valid
            // const roles = Object.values(foundUser.roles);
            const accessToken = jwt.sign(
                {
                    name: "James Santos",
                    email: "james.santos@payreto.com",
                },
                process.env.ACCESS_TOKEN_SECRET,
                { expiresIn: "10s" }
            );

            const newRefreshToken = jwt.sign(
                {
                    name: "James Santos",
                    email: "james.santos@payreto.com",
                },
                process.env.REFRESH_TOKEN_SECRET,
                { expiresIn: "15s" }
            );

            // Creates Secure Cookie with refresh token
            res.cookie("jwt", newRefreshToken, {
                httpOnly: true,
                secure: true,
                sameSite: "None",
                maxAge: 24 * 60 * 60 * 1000,
            });

            res.json({ accessToken });
        }
    );
});

app.post("/create", async (req, res) => {
    const connection = await mysql.createConnection({
        host: "localhost",
        user: "root",
        database: "disbursement",
    });

    const refreshToken = jwt.sign(
        {
            name: "James Santos",
            email: "james.santos@payreto.com",
        },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: "1h" }
    );

    const [rows, fields] = await connection.execute(
        "INSERT INTO users(name, email, password, refreshToken) VALUES(?, ?, ?, ?)",
        ["James Santos", "james.santos@payreto.com", "test1234", refreshToken]
    );

    console.log("rows", rows);

    return res.status(201).json({
        success: true,
        message: "Account created",
    });
});

// Login Handler
app.post("/auth", async (req, res) => {
    // Cookies
    const cookies = req.cookies;

    const connection = await mysql.createConnection({
        host: "localhost",
        user: "root",
        database: "disbursement",
    });

    const [rows, fields] = await connection.execute(
        "SELECT * FROM users WHERE email = 'james.santos@payreto.com'"
    );

    const { name, email } = rows[0];

    const accessToken = jwt.sign(
        { name, email },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: "10s" }
    );

    const newRefreshToken = jwt.sign(
        { name, email },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: "15s" }
    );

    // if (cookies?.jwt) {
    //     /*
    //     Scenario added here:
    //         1) User logs in but never uses RT and does not logout
    //         2) RT is stolen
    //         3) If 1 & 2, reuse detection is needed to clear all RTs when user logs in
    //     */
    //     const refreshToken = cookies.jwt;
    //     const foundToken = await connection.execute(
    //         "SELECT * FROM users WHERE refreshToken = ?",
    //         [refreshToken]
    //     );

    //     console.log("found", foundToken);

    //     // // Detected refresh token reuse!
    //     // if (!foundToken) {
    //     //     // clear out ALL previous refresh tokens
    //     //     newRefreshTokenArray = [];
    //     // }

    //     res.clearCookie("jwt", {
    //         httpOnly: true,
    //         sameSite: "None",
    //         secure: true,
    //     });
    // }

    const updateRefreshToken = await connection.execute(
        "UPDATE users SET refreshToken = ? WHERE email = ?",
        [newRefreshToken, email]
    );

    res.cookie("jwt", newRefreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "None",
        maxAge: 24 * 60 * 60 * 1000,
    });

    return res.json({
        user: {
            name: "James Santos",
            email: "james.santos@payreto.com",
        },
        accessToken,
    });
});

// Middleware
const verifyJWT = (req, res, next) => {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (!authHeader?.startsWith("Bearer ")) return res.sendStatus(401);
    const token = authHeader.split(" ")[1];
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        console.log("decoded", decoded);
        console.log("err", err);
        if (err) return res.sendStatus(403); //invalid token
        // req.user = decoded.user;
        next();
    });
};
app.use(verifyJWT);

app.get("/test", (req, res) => {
    return res.status(200).json({ success: true, message: "pasok" });
});

app.listen(5000, () => console.log("Server listening on port 5000"));
