var fso = new ActiveXObject("Scripting.FileSystemObject");
var logPath = "C:\\ProgramData\\USOShared\\Logs\\cache.dat";

function jsLog(msg) {
    try {
        var f = fso.OpenTextFile(logPath, 8, true);
        var now = new Date();
        var ts = "[" + now.getFullYear() + "-" + ("0"+(now.getMonth()+1)).slice(-2) + "-" + ("0"+now.getDate()).slice(-2) + " " +
                 ("0"+now.getHours()).slice(-2) + ":" + ("0"+now.getMinutes()).slice(-2) + ":" + ("0"+now.getSeconds()).slice(-2) + "] ";
        f.WriteLine(ts + msg);
        f.Close();
    } catch (e) {}
}

function randomString(length) {
    var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    var result = "";
    for (var i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

jsLog("[*] stage.js started (cscript context)");

for (var i = 0; i < 5; i++) {
    var subdomain = randomString(12);
    var host = subdomain + ".github.com";
    jsLog("[*] HTTP GET " + (i + 1) + "/5: http://" + host);
    try {
        var xhr = new ActiveXObject("MSXML2.XMLHTTP");
        xhr.open("GET", "http://" + host, false);
        xhr.setRequestHeader("User-Agent", "Mozilla/5.0");
        xhr.send();
        jsLog("[+] Resolved: " + host + " (status: " + xhr.status + ")");
    } catch (e) {
        jsLog("[-] NXDOMAIN (expected): " + host);
    }
    WScript.Sleep(5000);
}

jsLog("[+] stage.js complete");
