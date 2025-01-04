
// Hatch Engine Hook
// It should be used with Frida and any Hatch Engine game

// this should be used to hook "ResourceManager::LoadResource" function
// to get filenames

// tested with "Sonic Galactic" (Demo 2) PC game

// It should be executed like this:
// frida -l hatch_engine_frida_script.js -f SonicGalactic.exe



//  Version   Name               Date          Comment
//  v1.0      Bartlomiej Duda    04.01.2025    -


function get_current_datetime() {
	var today = new Date();
	var date = today.getFullYear()+'-'+(today.getMonth()+1)+'-'+today.getDate();
	var time = today.getHours() + ":" + today.getMinutes() + ":" + today.getSeconds();
	var dateTime = date+' '+time;
  return dateTime;
}

var module_name = 'SonicGalactic.exe';  // put here filename of EXE file from any Hatch Engine game


 var awaitForCondition = function (callback) {
     var int = setInterval(function () {
         var addr = Module.findBaseAddress(module_name);
         if (addr) {
             console.log("EXE Address found:", addr);
             clearInterval(int);
             callback(+addr);
             return;
         }
     }, 0);
 }
 
awaitForCondition((baseAddr)=>{
	console.log("STARTING HOOK ", get_current_datetime());
	
	
	var base_address = Module.findBaseAddress(module_name);
	const hatch_decryptaddr = base_address.add(0x136C6A);  // put here "LoadResource" function address
	
	console.log("[HATCH FUNC ADDRESS]-> ", hatch_decryptaddr);
	
	Interceptor.attach(hatch_decryptaddr, {
		
     onEnter(args) {
		 
	   this.output_filename = Memory.readCString(args[0]);
		 
	   console.log("[filename]-> " + this.output_filename);  // print filename
	   
	   var output_str = "[filename]-> " + this.output_filename;
	   console.log(output_str);
	   
	   
	   // dump filename to TXT file
		var out_file = new File("sonic_galactic_filenames.txt","at");
		out_file.write(this.output_filename + "\n");
		out_file.flush();
		out_file.close();
	   
     },
	 
	 onLeave: function ( retval ) {  

 		}
   })
	
});
