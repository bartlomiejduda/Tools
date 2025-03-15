
// Cocos2d XXTEA Script
// It should be used with Frida and any Android games 
// that are protected by XXTEA encryption


//  Version   Name               Date          Comment
//  v0.1      Bartlomiej Duda    04.09.2022    -


function get_current_datetime() {
	var today = new Date();
	var date = today.getFullYear()+'-'+(today.getMonth()+1)+'-'+today.getDate();
	var time = today.getHours() + ":" + today.getMinutes() + ":" + today.getSeconds();
	var dateTime = date+' '+time;
  return dateTime;
}


 var awaitForCondition = function (callback) {
     var int = setInterval(function () {
         var addr = Module.findBaseAddress('libcocos2djs.so');
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
	
	let xxtea_decryptaddr = Module.findExportByName('libcocos2djs.so', 'xxtea_decrypt');
	console.log("[XXTEA FUNC ADDRESS]-> ", xxtea_decryptaddr);
	
	Interceptor.attach(xxtea_decryptaddr, {
     onEnter(args) {
       console.log("[key]-> " + args[2].readCString()) // print XXTEA key 
     },
	 onLeave: function ( retval ) {  
			//console.log("Leaving export...")
 		}
   })
	
});
