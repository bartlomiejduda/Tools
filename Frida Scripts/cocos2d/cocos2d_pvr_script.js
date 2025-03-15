
// Cocos2d PVR Script
// It should be used with Frida and any Cocos2d game that is protected by PVR encryption
// Designed to hook "cocos2d::ZipUtils::setPvrEncryptionKeyPart(int,uint)" function


// It should be executed like this (one of the following):
// frida -U -l cocos2d_pvr_script.js -f jp.okakichi.chanran
// frida -l cocos2d_pvr_script.js -f PizzaBusiness.exe
// frida -U -l cocos2d_pvr_script.js -f com.tapblaze.pizzabusiness

// Example output: 
// [key]-> 0xf68c6273
// [key]-> 0x7c32116
// [key]-> 0x4af4f1ac
// [key]-> 0xbf0988a6


//  Version   Name               Date          Comment
//  v1.0      Bartlomiej Duda    16.12.2024    Initial version. Support for "jp.okakichi.chanran" (Android)
//  v1.1      Bartlomiej Duda    10.01.2025    Added support for "Good Pizza, Great Pizza" (PC)
//  v1.2      Bartlomiej Duda    14.01.2025    Added support for "Good Pizza, Great Pizza" v5.21.0 (Android)


function get_current_datetime() {
	var today = new Date();
	var date = today.getFullYear()+'-'+(today.getMonth()+1)+'-'+today.getDate();
	var time = today.getHours() + ":" + today.getMinutes() + ":" + today.getSeconds();
	var dateTime = date+' '+time;
  return dateTime;
}


// jp.okakichi.chanran (Android)
var module_name = 'libcgk.so';  
var export_name = '_ZN7cocos2d8ZipUtils23setPvrEncryptionKeyPartEij'; 


// "Good Pizza, Great Pizza" (PC)
var module_name = 'libcocos2d.dll';
var export_name = '?setPvrEncryptionKeyPart@ZipUtils@cocos2d@@SAXHI@Z'


// "Good Pizza, Great Pizza" v5.21.0 (Android) (com.tapblaze.pizzabusiness)
var module_name = 'libcocos2dcpp.so';
var export_name = '_ZN7cocos2d8ZipUtils23setPvrEncryptionKeyPartEij'


 var awaitForCondition = function (callback) {
     var int = setInterval(function () {
         var addr = Module.findBaseAddress(module_name);
         if (addr) {
             console.log("SO Address found:", addr);
             clearInterval(int);
             callback(+addr);
             return;
         }
     }, 0);
 }
 
awaitForCondition((baseAddr)=>{
	console.log("STARTING HOOK ", get_current_datetime());
	
	let pvr_decryptaddr = Module.findExportByName(module_name, export_name);
	console.log("[PVR FUNCTION ADDRESS]-> ", pvr_decryptaddr);
	
	Interceptor.attach(pvr_decryptaddr, {
		
     onEnter(args) {
	   console.log("[key]-> " + args[1]);  // print key part
     },
	 
	 onLeave: function ( retval ) {  

 		}
   })
	
});
