// Copyright © 2025  Bartłomiej Duda
// License: GPL-3.0 License

// Hook for "jp.co.cybird.android.conanescape01" v1.0
// Can be used to get ZIP password from game "Detective Conan X Escape Game: The Puzzle of a Room with Triggers" on Android

// Output --> [ZIP4J] Intercepted Password: h,s,9,j,Q,5,i,V,6,W,W,o,j,x,Y,i
// Real password --> hs9jQ5iV6WWojxYi

console.log("Starting hook!");

Java.perform(function() {
    var ActivityClass = Java.use("jp.co.cybird.android.conanescape01.gui.MainActivity");

    ActivityClass.onStart.implementation = function() {
        console.log("[*] onStart() start!");
        this.onStart();
        console.log("[*] onStart() finish!");
    };
});


Java.perform(function () {
    var FileHeader = Java.use("net.lingala.zip4j.model.FileHeader");

    FileHeader.setPassword.implementation = function (password) {
        console.log("[ZIP4J] Intercepted Password: " + password);
        return this.setPassword(password);
    };
});

console.log("End of hook!");
