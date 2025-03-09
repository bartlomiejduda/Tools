// Copyright © 2025  Bartłomiej Duda
// License: GPL-3.0 License

// Extra code for hooking "jp.co.cybird.android.conanescape01" v1.0
// not needed for main hook, but it may be helpful in some situations


// HOOK ON START METHOD #####################################################################

Java.perform(function() {
    var ActivityClass = Java.use("jp.co.cybird.android.conanescape01.gui.MainActivity");

    ActivityClass.onStart.implementation = function() {
        console.log("[*] onStart() start!");
        this.onStart();
        console.log("[*] onStart() finish!");
    };
});




// ENUMERATE METHODS IN CLASS #########################################################
function enumMethods(targetClass)
{
  var hook = Java.use(targetClass);
  var ownMethods = hook.class.getDeclaredMethods();
  hook.$dispose;

  return ownMethods;
}

setTimeout(function() { // avoid java.lang.ClassNotFoundException
  Java.perform(function() {
    var a = enumMethods("jp.co.cybird.android.conanescape01.gui.MainActivity")
    a.forEach(function(s) { 
      console.log(s); 
    });
  });
}, 0);




// a.a.a.b.c HOOK    #########################################################
Java.perform(function() {
    var MyClass = Java.use("a.a.a.b.c");  
    
    MyClass.a.overload("[B").implementation = function(byteArray) {
        console.log("Hooked method a([B)V");

        var buffer = Java.array('byte', byteArray);
        var str = "";
        for (var i = 0; i < buffer.length; i++) {
            str += String.fromCharCode(buffer[i]);
        }
        console.log("Input byte array: " + str);

        this.a(byteArray);

        console.log("Original method executed.");
    };
});




// check what ZIP files are opened by java.util.zip ##################################

Java.perform(function () {
    var ZipFile = Java.use("java.util.zip.ZipFile");

    ZipFile.$init.overload("java.lang.String").implementation = function (filePath) {
        console.log("ZIP file opened: " + filePath);
        return this.$init(filePath);
    };

    ZipFile.getInputStream.implementation = function (entry) {
        console.log("ZIP entry accessed: " + entry.getName());
        return this.getInputStream(entry);
    };
});



// hook string.valueof  ###################################################
Java.perform(function () {
    var StringClass = Java.use("java.lang.String");
	
    StringClass.valueOf.overload("java.lang.Object").implementation = function (obj) {
        var result = this.valueOf(obj);
        console.log("Result: " + result);
        return result;
    };
});



// hook for getting ZIP password from "jp.co.cybird.android.conanescape02" v1.0.0
// Password --> waU8uqL1V30IwRgLdIAfemlrpbvVh2v3
Java.perform(function() {
    var targetClass = "a.a.a.e.f";
    var targetMethod = "a";

    var clazz = Java.use(targetClass);
    
    clazz[targetMethod].overload("[C").implementation = function(charArray) {
        console.log("Original input: " + JSON.stringify(charArray));
        
        this[targetMethod](charArray);
    };
});
