#include <vector>
#include <unordered_map>
#include <algorithm>
#include <iostream>
#include "nlohmann/json.hpp"
#include "pbc.h"
#include "pbc_utils.h"  // for UNUSED_VAR
#include <fstream>
#include <iomanip>
#include <iostream>
#include "MABE.hpp"

using json = nlohmann::json;
//Compile with: g++ MABE-decrypt.cpp -o MABE-decrypt -lpbc -lgmp -I /usr/local/include/pbc

int main() {
    std::ifstream jsonFile ( "public.json", std::ios::in );
    json publicInfo = json::parse( jsonFile );

    pairing_t pairing;
    char param[1024];
    size_t count = fread(param, 1, 1024, fopen("a.param","r"));
    if (!count) pbc_die("input error");
    pairing_init_set_buf(pairing,param, count);

    element_t msg, decrypted_msg;
    element_init_GT(msg, pairing); element_init_GT(decrypted_msg, pairing);

    //For testing decryption, include the message or key here.
    element_from_hash(msg, (void*)"Hello", 5);

    //Otherwise use a zero value for message.
    //element_set0(zero);

    element_t g1, g2, e_g1g2;
    element_init_G1(g1,pairing);
    element_init_G2(g2,pairing);
    element_init_GT(e_g1g2, pairing);

    convertFromString(g1, publicInfo["g1"]);
    convertFromString(g2, publicInfo["g2"] );
    convertFromString(e_g1g2, publicInfo["e_g1g2"] );

    std::ifstream encryptJson ( "encrypt.json", std::ios::in );
    json enc_msg = json::parse( encryptJson );

    std::ifstream userInfoJson ( "userInfo.json", std::ios::in );
    json userInfo = json::parse( userInfoJson );
    //element_printf("%B\n", msg);

    decrypt( enc_msg, userInfo, pairing, g1, g2, e_g1g2, msg, decrypted_msg); 

    //////////////////Testing///////////////////////
    char s[500];
    mpz_t side1;
    mpz_init(side1);    
    mpz_t side2;
    mpz_init(side2);
    mpz_t D1;
    mpz_init(D1);    
    mpz_t D2;
    mpz_init(D2);
    std::string str = enc_msg["D1"];
    mpz_set_str(D1, str.c_str(), 10);   
    str = enc_msg["D2"];
    mpz_set_str(D2, str.c_str(), 10);
    //element_printf("%B\n", decrypted_msg);
    element_snprint(s, 400, decrypted_msg);    

    str = SplitString(s, '[')[1];
    str = SplitString(str, ']')[0];    
    mpz_set_str(side1, SplitString(str, ',')[0].c_str(),  10);    
    mpz_set_str(side2, SplitString(str, ',')[1].c_str(), 10);    
    mpz_sub(side1, side1, D1);
    mpz_sub(side2, side2, D2);

    gmp_printf("%ZX%ZX\n", side1, side2); 
    //////////////////Testing///////////////////////

    //std::cout<<"Decryption complete.\n";
    return 0; 
}