const fs = require("fs");
const express = require("express");
const crypto = require("crypto");
const axios = require("axios").default;
const sqlite3 = require('sqlite3');
const aes256 = require('aes256');
const { reset } = require("nodemon");
const https = require('https');
const http = require('http');
const cors = require('cors');
var app = express();
var httpPort = 9870;
var httpsPort = 9871;
var adminPassword = "e316d90fb2dd942ca7e30caffa58bbb77c9a6e3ff94ddd6f4ce145907c5ee534";
var cachedIds = [];
app.use(cors({
    origin: "*",
}));
app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    next();
});
app.use(express.json());

const hash = text => crypto.createHash("sha1").update(text).digest("base64");
const readJson = path => JSON.parse(fs.readFileSync(path, { encoding: "utf8" }));
var config = readJson("config.json");
var db = new sqlite3.Database(config.dbPath, error => {
    if (error) return process.exit("Couldn't connect to database!");
    console.log("Connected to database!");
    db.run("CREATE TABLE IF NOT EXISTS keys (id INTEGER PRIMARY KEY AUTOINCREMENT, secret TEXT, security TEXT, deadlineMS TEXT, deadlineText TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS misc (id INTEGER PRIMARY KEY AUTOINCREMENT, downloadCount TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS ids (id INTEGER PRIMARY KEY AUTOINCREMENT, downloadId TEXT, secret TEXT NOT NULL, lastDownload TEXT NOT NULL, FOREIGN KEY(secret) REFERENCES keys(secret))");
});
const insertToKeys = (secret, security, deadlineMS, deadlineText) => {
    db.run("INSERT INTO keys (secret, security, deadlineMS, deadlineText) VALUES (?, ?, ?, ?)", [secret, security, deadlineMS, deadlineText], (err, res) => { if (err) console.log("ERR while INSERT process", err); console.log(res); });
};
const insertToMisc = (downloadCount) => {
    db.run("INSERT INTO misc (downloadCount) VALUES (?)", [downloadCount], (err, res) => { if (err) console.log("ERR while INSERT process", err); console.log(res); });
};
const insertToIds = (downloadId, secret, lastDownload) => {
    db.run("INSERT INTO ids (downloadId, secret, lastDownload) VALUES (?, ?, ?)", [downloadId, secret, lastDownload]), (err, res) => { if (err) console.log("ERR while INSERT process", err); console.log(res); };
};
const update = (id, secret, security, deadlineMS, deadlineText) => {
    db.run("UPDATE keys SET secret=?, security=?, deadlineMS=?, deadlineText=? where id=? or secret = ?", [secret, security, deadlineMS, deadlineText, id, id], (err, res) => { if (err) console.log("ERR while UPDATE process", err); console.log(res); });
};
const updateKey = (id, key, value, table="keys") => {
    db.run(`UPDATE ${table} SET ${key}=? where id=? or secret = ?`, [value, id, id], (err, res) => { if (err) console.log("ERR while single-UPDATE process", err); console.log(res); });
}
const updateMisc = (key, value) => {
    db.run(`UPDATE misc SET ${key}=? where id=?`, [value, 1], (err, res) => { if (err) console.log("ERR while single-UPDATE process", err); console.log(res); });
}
const updateAllKey = (key, value) => {
    db.run(`UPDATE keys SET ${key}=?`, [value], (err, res) => { if (err) console.log("ERR while single-UPDATE process", err); console.log(res); });
}
const selectAll = (table = "keys") => {
    return new Promise(r => db.all(`SELECT * FROM ${table}`, (error, result) => {
        if (error) console.log("ERR while SELECT process", error);
        r(result);
    }));
};
const selectBySecret = (secret, table = "keys")=> {
    return new Promise(r => db.all(`SELECT * FROM ${table} WHERE secret = ?`, [secret], (error, result) => {
        if (error) console.log("ERR while SELECT process", error);
        r(result);
    }));
};
const selectById = id => {
    return new Promise(r => db.all("SELECT * FROM keys WHERE id = ?", [id], (error, result) => {
        if (error) console.log("ERR while SELECT process", error);
        r(result);
    }));
};
const delete_ = (value, table="keys") => {
    return new Promise(r => db.all(`DELETE FROM ${table} WHERE id = ? or secret=?`, [value, value], (error, result) => {
        if (error) console.log("ERR while SELECT process", error);
        r(result);
    }));
};
const deleteAll = (table="keys") => {
    return new Promise(r => db.all(`DELETE FROM ${table}`, (error, result) => {
        if (error) console.log("ERR while SELECT process", error);
        r(result);
    }));
};
const a = value => value.toString().length < 2 ? "0" + value : value;
const nT = value => value === "null" ? null : value;
const cpass = request => request.headers.password === adminPassword;
const beautify = (object, space = 2) => JSON.stringify(object, null, space);
const timestampToDate = timestamp => { var d = new Date(timestamp); return `${a(d.getHours())}:${a(d.getMinutes())}:${a(d.getSeconds())}, ${a(d.getDate())} ${a(['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'][d.getMonth()])} ${a(d.getFullYear())}`; };
const downloadCheck = async (request, r, passSuccessResponse = false) => {
    const res = (message, url, fileName, error = false, status = 200) => [r.status(status), r.send(beautify({ error: error, message: message, url: url, fileName: fileName }))];
    try {
        request.headers.security = request.query.security ? request.query.security : request.headers.security;
        if (!request.headers.security) return res("H-Fail check!", true);
        var id = nT(request.query.id);
        var securityData = request.headers.security.split(":");
        var securityValue = "";
        if (!securityData || ((typeof securityData === typeof "") && securityData.length < 10))
            return res("Enter secret key!", true);
        securityValue = securityData[1];
        if (securityValue.length <= 9)
            return res("Invalid password!", true);
        var secret = securityData[0];
        var filtered = await selectBySecret(secret);
        if (filtered.length < 1) return res("Invalid secret key!", null, null, true);
        filtered = filtered[0];
        if (filtered.security !== "" && filtered.security !== securityValue) return res("Invalid IP! Contact with an administrator..", null, null, true);
        if (filtered.security === "") {
            update(filtered.id, filtered.secret, securityValue, filtered.deadlineMS, filtered.deadlineText);
        }
        var ids = await selectBySecret(secret, "ids");
        var downloadId = "";
        if (ids.length < 1){
            downloadId = crypto.randomBytes(35).toString("hex");
            await insertToIds(downloadId, secret, Date.now()+ "");
        }
        else {
            downloadId = ids[0].downloadId;
            if ((Date.now() - parseInt(ids[0].lastDownload)) > (1000 * 60 * 60 * 1)  && !config.passDownloadIDCheck)
                return res("Download limit exceed!", null, true, 200);
            // await insertToIds(downloadId, secret, Date.now()+ "");
        }
        passSuccessResponse !== true && res("Success!", downloadId, config.sendStaticFile ? config.staticFile : nT(request.query.file), false, 200);
    } catch (error) {
        res(`${error}`);
    }
};
app.get("/files", async (request, r) => {
    const res = (message, files, error = false, status = 200) => [r.status(status), r.send(beautify({ error: error, message: message, files: files }))];
    if (cpass(request)) {
        return res("Success!", fs.readdirSync(config.filesPath), false, 200);
    }
    res("Permission denied!", [], true, 401);
});
app.delete("/file", async (request, r) => {
    const res = (message, error = false, status = 200) => [r.status(status), r.send(beautify({ error: error, message: message }))];
    if (cpass(request)) {
        var file = nT(request.body.file);
        if (fs.existsSync(file))
            fs.rm(`${config.filesPath}/${file}`);
        return res("Success!", false, 200);
    }
    res("Permission denied!", [], true, 401);
});
app.put("/file", async (request, r) => {
    const res = (message, error = false, status = 200) => [r.status(status), r.send(beautify({ error: error, message: message }))];
    if (cpass(request)) {
        var file = nT(request.body.file);
        var fileName = nT(request.body.fileName);
        fs.writeFileSync(`${config.filesPath}/${fileName}`, Buffer.from(file));
        return res("Success!", false, 200);
    }
    res("Permission denied!", [], true, 401);
});
app.get("/config", async (request, r) => {
    const res = (message, config, error = false, status = 200) => [r.status(status), r.send(beautify({ error: error, message: message, config: config }))];
    config = readJson("config.json");
    cpass(request) ? res("Success!", config, false, 200) : res("Permission denied!", {}, true, 502);
});
app.put("/config", async (request, r) => {
    const res = (message, config, error = false, status = 200) => [r.status(status), r.send(beautify({ error: error, message: message, config: config }))];
    if (cpass(request)) {
        fs.writeFileSync("config.json", JSON.stringify(request.body, null, 4), { encoding: "utf8" });
        config = readJson("config.json");
        return res("Success!", config, false, 200);
    }
    res("Permission denied!", {}, true, 401);
});
app.get("/info", async (request, r) => {
    const res = (message, downloads, error = false, status = 200) => [r.status(status), r.send(beautify({ error: error, message: message, downloads: downloads }))];
    var misc = await selectAll("misc");
    if (misc.length < 1) {
        insertToMisc(config.defaultDownloadCountValue);
        misc = {};
        misc.downloadCount = config.defaultDownloadCountValue;
        misc = [misc];
    }
    misc = misc[0];
    res("Success!", misc.downloadCount, false, 200);
});
app.put("/info", async (request, r) => {
    const res = (message, downloads, error = false, status = 200) => [r.status(status), r.send(beautify({ error: error, message: message, downloads: downloads }))];
    if (cpass(request)) {
        var misc = await selectAll("misc");
        if (misc.length < 1) {
            insertToMisc(config.defaultDownloadCountValue);
            misc = {};
            misc.downloadCount = config.defaultDownloadCountValue;
            misc = [misc];
        }
        misc = misc[0];
        var downloadCount = request.body.downloadCount ? request.body.downloadCount : misc.downloadCount;
        await updateMisc("downloadCount", downloadCount);
        return res("Success!", downloadCount, false, 200);
    }
    res("Permission denied!", 0, true, 401);
});
app.get("/keys", async (request, r) => {
    const res = (message, keys, error = false, status = 200) => [r.status(status), r.send(beautify({ error: error, message: message, keys: keys }))];
    if (cpass(request)) {
        var id = nT(request.body.id);
        var secret = nT(request.body.secret);
        return res("Success!", await (id ? selectById(id) : secret ? selectBySecret(secret) : selectAll()), false, 200);
    }
    res("Permission denied!", [], true, 401);
});
app.delete("/delete", async (request, r) => {
    const res = (message, error = false, status = 200) => [r.status(status), r.send(beautify({ error: error, message: message }))];
    if (cpass(request)) {
        var value = nT(request.body.value);
        await (value ? delete_(value) : deleteAll());
        await (value ? delete_(value, "ids") : deleteAll("ids"));
        return res("Success!", false, 200);
    }
    res("Permission denied!", true, 401);
});
app.post("/generate", async (request, r) => {
    const res = (message, generated, deadlineMS, deadlineText, error = false, status = 200) => [r.status(status), r.send(beautify({ error: error, message: message, deadlineMS: deadlineMS, deadlineText: deadlineText, keys: generated }))];
    if (cpass(request)) {
        var count = nT(request.body.count);
        var days = nT(request.body.d) ? nT(request.body.d) : (365 * 25);
        var deadlineMS = Date.now() + (parseInt(days + "") * 1000 * 60 * 60 * 24);
        var addedKeys = [];
        for (let index = 0; index < count; index++) {
            var key = crypto.randomBytes(32).toString("hex");
            insertToKeys(key, "", deadlineMS.toString(), timestampToDate(deadlineMS));
            addedKeys.push(key);
        }
        return res("Success!", addedKeys, deadlineMS, timestampToDate(deadlineMS), false, 200);
    }
    res("Permission denied!", [], 0, "0", true, 401);
});
app.post("/resetSecurity", async (request, r) => {
    const res = (message, error = false, status = 200) => [r.status(status), r.send(beautify({ error: error, message: message }))];
    if (cpass(request)) {
        var value = nT(request.body.value);
        await (value ? updateKey(value, "security", "") : updateAllKey("security", ""));
        return res("Success!", false, 200);
    }
    res("Permission denied!", true, 401);
});
app.put("/update", async (request, r) => {
    const res = (message, error = false, status = 200) => [r.status(status), r.send(beautify({ error: error, message: message }))];
    if (cpass(request)) {
        var id = nT(request.query.id);
        var secret = nT(request.query.secret);
        var security = nT(request.query.security);
        var days = nT(request.query.d);
        var deadlineMS = nT(request.query.deadlineMS) ? nT(request.query.deadlineMS) : (days ? (Date.now() + (parseInt(days + "") * 1000 * 60 * 60 * 24)) : null);
        var d = await selectById(id);
        if (d.length < 1) return res("Invalid ID!", true);
        d = d[0];
        await update(id, secret ? secret : d.secret, security ? security : d.security, deadlineMS ? deadlineMS : d.deadlineMS, timestampToDate(parseInt(deadlineMS ? deadlineMS : d.deadlineMS)));
        return res("Success!", false, 200);
    }
    res("Permission denied!", true, 401);
});
app.get("/checkDownload", downloadCheck);
app.get("/download", async (request, r) => {
    const res = (message, error = false, status = 200) => [r.status(status), r.send(beautify({ error: error, message: message }))];
    downloadCheck(request, r, true);
    try {
        var id = nT(request.query.id);
        var secret = nT(request.headers.security.toString().split(":")[0]);
        var ids = await selectBySecret(secret, "ids");
        if(ids[0].downloadId !== id && !config.passDownloadIDCheck)
            return res("Invalid download id!", true, 200);
        downloadId = crypto.randomBytes(35).toString("hex");
        await updateKey(secret, "downloadId", downloadId, "ids");
        await updateKey(secret, "lastDownload", Date.now() + "", "ids");
        var file = nT(request.query.file);
        if (config.sendStaticFile) file = config.staticFile;
        var path = `${config.filesPath}/${file}`;
        console.log(file);
        if (!fs.existsSync(path))
            return res(`Couldn\'t find file specified! File: "${file}"`);
        var misc = await selectAll("misc");
        if (misc.length < 1) {
            insertToMisc(config.defaultDownloadCountValue);
            misc = {};
            misc.downloadCount = config.defaultDownloadCountValue;
            misc = [misc];
            console.log(misc);
        } else {
            var newVal = parseInt(misc[0].downloadCount) + 1;
            db.run("UPDATE misc SET downloadCount = ? where id=1", [newVal.toString()], (err, response) => { if (err) console.log("ERROR while UPDATE", err); console.log("UPDATED misc! New value:", newVal); });
        }
        var buf = fs.readFileSync(path);
        console.log(buf.length, buf.slice(0, 10));
        r.download(`${path}`);
        // r.send(beautify({ "error": false, "message": "Success!", "content": buf, "fileName": file }));
    } catch (error) {
        r.send(beautify({ "error": true, "message": `${error}`, "content": null, "fileName": null }));
    }
});

https.createServer({
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.cert')
}, app).listen(httpsPort, () => {
    console.log(`Running HTTPS at ${httpsPort}`);
});
app.listen(httpPort, () => {
    console.log(`Running HTTP at ${httpPort}`);
});