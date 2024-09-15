
// Good Pizza Great Pizza frida hook
// It should be used with Frida and "Good Pizza Great Pizza" game on PC


//  Version   Name               Date          Comment
//  v1.0      Bartlomiej Duda    15.09.2024    -


// It attaches to sub_72AE93D0 which is called by "getFileDataFromEncryptedZip" function from libcocos2d.dll


console.log("Getting info...");
var module_name = 'libcocos2d.dll';
var base_address = Module.findBaseAddress(module_name);

console.log("BASE_ADDRESS: " + base_address);

console.log("Starting frida hook...");
//const password_function_address = Module.findExportByName('libcocos2d.dll', 'getFileDataFromEncryptedZip');
const password_function_address = base_address.add(0x993D0);
console.log("PASSWORD_FUNCTION_ADDRESS: " + password_function_address);

Interceptor.attach(password_function_address, {

    onEnter: function(args)
    {
		this.arg0 = args[0].toInt32();
		this.arg1 = args[1].toInt32();
		this.arg2 = args[2].toInt32();
		this.arg3 = args[3].toInt32();
		this.arg4 = Memory.readCString(args[4]);
    },

	onLeave: function ( retval )
	{
		var output_str = "ZIP_PASSWORD=\"" + this.arg4 + "\"";
		console.log(output_str);
 	}

});
