
// Room Of Prey Frida Script
// It should be used with Frida and any game from "Room Of Prey" series
// Designed to hook "MIDASKernelManager::hash" function


// It should be executed like this:
// frida -U -l room_of_prey_frida_script.js -f co.kr.eamobile.roomofprey3

// Example output: 
// snd/S_EFF_31.ogg ||| 0xc7a248a
// t/T_SYS ||| 0x58eb299a
// i/IMG_GRADE_12 ||| 0x2293745e



//  Version   Name               Date          Comment
//  v1.0      Bartlomiej Duda    07.09.2025    Initial version



function get_current_datetime() {
	var today = new Date();
	var date = today.getFullYear()+'-'+(today.getMonth()+1)+'-'+today.getDate();
	var time = today.getHours() + ":" + today.getMinutes() + ":" + today.getSeconds();
	var dateTime = date+' '+time;
  return dateTime;
}



// Room Of Pray 3 (Android) (co.kr.eamobile.roomofprey3)
var module_name = 'libroomofprey3.so';
var export_name = '_ZN18MIDASKernelManager4hashEPh'



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
	
	let hash_function_address = Module.findExportByName(module_name, export_name);
	console.log("[HASH FUNCTION ADDRESS]-> ", hash_function_address);
	
	Interceptor.attach(hash_function_address, {
		
     onEnter(args) {
	   this.hash_string = Memory.readCString(args[1]);
     },
	 
	 onLeave: function ( retval ) {  
		var output_str = this.hash_string + " ||| " + retval;  // e.g. snd/S_EFF_31.ogg ||| 0xc7a248a
		console.log(output_str);
 		}
   })
	
});
