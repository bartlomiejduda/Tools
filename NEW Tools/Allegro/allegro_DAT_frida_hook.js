
// Allegro DAT frida hook
// It should be used with Allegro Engine games (e.g. Head Over Heels)


//  Version   Name               Date          Comment
//  v1.0      Bartlomiej Duda    21.07.2024    -



console.log("Starting frida hook...");
const password_function_address = Module.findExportByName('alleg40.dll', 'packfile_password');
console.log("PASSWORD_FUNCTION_ADDRESS: " + password_function_address);

const fopen_function_address = Module.findExportByName('alleg40.dll', 'pack_fopen');
console.log("F_OPEN_FUNCTION_ADDRESS: " + fopen_function_address);


Interceptor.attach(fopen_function_address, {
	
    onEnter: function(args)
    {	
		var allegro_filename = Memory.readCString(args[0]);
		console.log("Opening " + allegro_filename + " file...");
    },
	
	onLeave: function ( retval ) 
	{  
 	}
	
});


Interceptor.attach(password_function_address, {
	
    onEnter: function(args)
    {	
		this.allegro_password = Memory.readCString(args[0]);
    },
	
	onLeave: function ( retval ) 
	{  
		var output_str = "PASSWORD=\"" + this.allegro_password + "\"";
		console.log(output_str);
 	}
	
});

