

// Ver    Date        Name
// v1.0   06.06.2019  Bartlomiej Duda
// v1.1   07.06.2019  Bartlomiej Duda
// v1.2   08.06.2019  Bartlomiej Duda
// v1.3   09.06.2019  Bartlomiej Duda
// v1.4   10.06.2019  Bartlomiej Duda
// v1.5   23.02.2020  Bartlomiej Duda

#include "pch.h"
#include "Hash_func.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <ctime>
#include <chrono>
#include <thread>
#include <windows.h>
#include <mutex>
#include <cmath>
#include <conio.h>


using namespace std;

#pragma warning(disable: 4996)

#pragma warning(disable: 4267) //size_t to int conversion warning
#pragma warning(disable: 4244) //unsigned_int64 to unsigned long warning


string current_date()
{
	std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
	char buf[100] = { 0 };
	std::strftime(buf, sizeof(buf), "%d/%m/%Y %H:%M:%S", localtime(&now));
	return buf;
}

string format_time(int time)
{
	int hour = time / 3600;
	time = time % 3600;
	int min = time / 60;
	time = time % 60;
	int sec = time;

	std::stringstream out_ss;
	out_ss << hour << ":" << min << ":" << sec;
	std::string out = out_ss.str();

	return out;
}



void log_data(string fun, string message, bool append_enters)
{
	string enters;
	if (append_enters == true)
		enters = "\n\n\n\n\n";
	else
		enters = "";

	ofstream myfile;
	myfile.open("logs.txt", ios::app);
	myfile << enters << current_date() << " LOG " + fun + " " + message + "\n";
	myfile.close();
}







unsigned long  str_hash_to_int(char *input_hash)
{
	unsigned long result = 0;
	std::stringstream ss;
	ss << std::hex << setfill('0') << setw(8) << input_hash;
	ss >> result;
	return result;
}


int check_hash(char* str, unsigned long s_hash)
{
	unsigned long h_hash = calculate_hercules_hash(str);
	//unsigned long s_hash = str_hash_to_int(s_hash_str);

	if (h_hash == s_hash)
	{
		cout << endl;
		cout << "Hash cracked!" << endl;
		cout << "h_hash: " << h_hash << " s_hash: " << s_hash << endl;
		cout << "str: " << str << endl;


		std::stringstream log_string_ss;
		log_string_ss << "Hash cracked! " << "h_hash: " << h_hash << " s_hash: " << s_hash << " str: " << str;
		std::string log_string = log_string_ss.str();
		log_data("CHECK_HASH_010", log_string, false);


		return 0;
	}

	return -1;
}


/*static string const digits =	"abcdefghijklmnopqrstuvwxyz"     //set of characters allowed to use for cracking
								"ABCDEFGHIJKLMNOPQRSTUVWXYZ"     //different sets below
								"0123456789"
								".\\_";*/


//static string const digits = "abcd.\\_f";

static string const digits =	"eus"
								"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
								"12"
								".\\";


string increment(string value) 
{
	string result;
	bool carry = true;
	for (int i = value.size() - 1; i >= 0; --i) 
	{
		int v = digits.find(value.at(i));
		v += carry;
		carry = v >= digits.size();
		v = carry ? 0 : v;
		result.push_back(digits.at(v));
	}
	reverse(begin(result), end(result));
	return result;
}

bool compare_digits(char a, char b) 
{
	int va = digits.find(a);
	int vb = digits.find(b);
	return va < vb;
}

bool compare(string const& a, string const& b) 
{
	return lexicographical_compare(begin(a), end(a), begin(b), end(b), compare_digits);
}

string generate_initial(int len)
{
	string out;
	for (int i = 0; i < len; i++)
		out += "a";

	return out;
}

mutex m;
string thread_current_word;
string time_el;
std::condition_variable cv;
unsigned long long word_counter = 0;
bool ready = false;
unsigned long word_speed;
int crack_result = -1;
bool length_goal_met = false;


void initiate_cracking()
{
	char input_c_str[100] = "M:\\GRAFIX\\CHOP\\SRC1\\ALIEN2\\Zeus\\ANIMPSX.BIN";
	char s_hash_c_str[] = "005C2A6A";
	unsigned long s_hash = str_hash_to_int(s_hash_c_str);
	int start_len = 36;
	int stop_len = 36;



	std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();

	for (int i = start_len; i <= stop_len; i++) //loop for incrementing initial string length
	{

		string initial = generate_initial(i);


		std::stringstream log_string_ss;
		log_string_ss << "Starting loop, " << "word length: " << i;
		std::string log_string = log_string_ss.str();
		log_data("INIT_CRACK_010", log_string, false);


		string generated_string = initial;
		string last;
		do {


			last = generated_string;
			generated_string = increment(last);


			strcpy_s(input_c_str, generated_string.c_str());
			crack_result = check_hash(input_c_str, s_hash);
			//cout << generated_string << '\n';

			if (crack_result == 0)
			{
				return; //hash found, stopping thread
			}

			m.lock();
			thread_current_word = generated_string;

			std::stringstream time_el_ss;
			std::chrono::steady_clock::time_point curr_time = std::chrono::steady_clock::now();
			time_el_ss << (std::chrono::duration_cast<std::chrono::microseconds>(curr_time - begin).count()) / 1000000.0;
			time_el = time_el_ss.str();
			
			word_counter += 1;
			m.unlock();


		} while (compare(last, generated_string));  //loop for checking each combination of size len(initial)


		log_string_ss;
		log_string_ss << "End of loop, " << "word length: " << i;
		log_string = log_string_ss.str();
		log_data("INIT_CRACK_020", log_string, false);

	}

	length_goal_met = true; //All combinations have been checked, but no hash has been found
	log_data("INIT_CRACK_030", "All combinations for desired length have been checked. Finishing work...", false);
	cout << "All combinations for desired length have been checked. Finishing work..." << endl;
	return;

	
}



void get_word_speed()
{
	while (1)
	{
		unsigned long word_speed_loc_1 = word_counter;
		Sleep(1000);
		unsigned long word_speed_loc_2 = word_counter;

		m.lock();
		word_speed = word_speed_loc_2 - word_speed_loc_1;
		m.unlock();

		if (crack_result == 0)
		{
			return; //hash found, stopping thread
		}

		if (length_goal_met == true)
		{
			return; //length goal met, but hash was not found, stopping thread
		}
	}
	
}


void log_to_console()
{
	bool cout_switch = true;
	unsigned long con_counter = 0;

	while (1)
	{

		if (GetAsyncKeyState(VK_SPACE))
		{
			if (cout_switch == true)
				cout_switch = false;
			else
				cout_switch = true;
		}

		if (cout_switch == true)
		{
			Sleep(1000);
			cout << "Time_elapsed: " << time_el << " Curr_word: " << thread_current_word << " Word_count: " << word_counter << " Word speed: " << word_speed << "\\s" << endl;
			con_counter += 1;

			if (crack_result == 0)
			{
				return; //hash found, stopping thread
			}

			if (length_goal_met == true)
			{
				return; //length goal met, but hash was not found, stopping thread
			}


			if (con_counter % 10 == 0)
			{
				std::stringstream log_string_ss;
				log_string_ss << "Time_elapsed: " << time_el << " Curr_word: " << thread_current_word << " Word_count: " << word_counter << " Word speed: " << word_speed << "\\s";
				std::string log_string = log_string_ss.str();
				log_data("LOG_TO_CONSOLE_010", log_string, false);
			}
		}
		
	}



}


int main(int argc, char* argv[])
{
	cout << "Hash Cracker by Bartlomiej Duda\n";

	log_data("MAIN_010", "Starting Hash Cracker", true);


	const char* mode ="TESTMODE";
	const char* funct = "HERC_FUNCT";


	if (strcmp(mode, "TESTMODE") == 0)
	{
		std::cout << "TEST MODE INITIALIZED" << std::endl;

		if (strcmp(funct, "HERC_FUNCT") == 0)
		{
			char input_c_str[100] = "M:\\GRAFIX\\CHOP\\SRC1\\ALIEN2\\Zeus\\ANIMPSX.BIN";
			char s_hash_c_str[] = "005C2A6A";
			unsigned long s_hash = str_hash_to_int(s_hash_c_str);
			crack_result = check_hash(input_c_str, s_hash);
			if (crack_result == 0)
			{
				//hash found
				std::cout << "CRASCKING WAS SUCCESSFULL" << std::endl;
			}

		}
		else if (strcmp(funct, "SILENT_HILL_FUNCT") == 0)
		{

		}
		else
		{
			std::cout << "No function to test selected. Exiting..." << std::endl;
		}

	}
	else if (strcmp(mode, "CRACKMODE") == 0)
	{
		thread th2(log_to_console);
		thread th3(get_word_speed);
		thread th1(initiate_cracking);


		th2.join();
		th3.join();
		th1.join();
	}
	else
	{
		std::cout << "No mode selected. Exiting... " << std::endl;
	}




	log_data("MAIN_020", "Hash Cracker STOP", false);

	char tmp = getch();
	return 0;
}

