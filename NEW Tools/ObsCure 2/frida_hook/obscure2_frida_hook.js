
// Obscure 2 frida hook
// It should be used with Frida and "Obscure 2" game on PC


//  Version   Name               Date          Comment
//  v0.1      Bartlomiej Duda    17.12.2022    -



console.log("Getting info...");
var module_name = 'Obscure2.exe';
var base_address = Module.findBaseAddress(module_name);
const hash_function_address = base_address.add(0x194510);

console.log("BASE_ADDRESS: " + base_address);
console.log("HASH_FUNCTION_ADDRESS: " + hash_function_address);



Interceptor.attach(hash_function_address, {
	
    onEnter: function(args)
    {	
		this.hash_str = Memory.readCString(args[0]);
		this.str_len = args[1].toInt32();
    },
	
	onLeave: function ( retval ) 
	{  
		var output_str = "HASH_VAL=" + retval + "\tSTR_LEN=" + this.str_len + "\tSTR=" + this.hash_str;
		console.log(output_str);
		
		var out_file = new File("C:\\Users\\UserName\\Desktop\\obscure_frida_hash_dump.txt","at");
		out_file.write(output_str + "\n");
		out_file.flush();
		out_file.close();
 	}
	
});