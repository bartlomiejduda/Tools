
// Cocos2d PVR Script
// It should be used with Frida and any Android games 
// that are protected by PVR encryption
// this should be used to hook "cocos2d::ZipUtils::setPvrEncryptionKeyPart(int,uint)" function

// works fine with "jp.okakichi.chanran" package

// It should be executed like this:
// frida -U -l cocos2d_pvr_script.js -f jp.okakichi.chanran

// Example output: 
// [PVR FUNC ADDRESS]->  0x71891f9340
// [key]-> 0xf68c6273
// [key]-> 0x7c32116
// [key]-> 0x4af4f1ac
// [key]-> 0xbf0988a6


//  Version   Name               Date          Comment
//  v1.0      Bartlomiej Duda    16.12.2024    -


function get_current_datetime() {
	var today = new Date();
	var date = today.getFullYear()+'-'+(today.getMonth()+1)+'-'+today.getDate();
	var time = today.getHours() + ":" + today.getMinutes() + ":" + today.getSeconds();
	var dateTime = date+' '+time;
  return dateTime;
}


 var awaitForCondition = function (callback) {
     var int = setInterval(function () {
         var addr = Module.findBaseAddress('libcgk.so');  // libcocos2djs.so
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
	
	let pvr_decryptaddr = Module.findExportByName('libcgk.so', '_ZN7cocos2d8ZipUtils23setPvrEncryptionKeyPartEij');  // libcocos2djs.so     _ZN7cocos2d8ZipUtils19setPvrEncryptionKeyEjjjj
	console.log("[PVR FUNC ADDRESS]-> ", pvr_decryptaddr);
	
	Interceptor.attach(pvr_decryptaddr, {
		
     onEnter(args) {
	   console.log("[key]-> " + args[1]);  // print key part
     },
	 
	 onLeave: function ( retval ) {  

 		}
   })
	
});
