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
//Compile with: g++ MABE-encrypt.cpp -o MABE-encrypt -lpbc -lgmp -I /usr/local/include/pbc

int main() {
    std::ifstream jsonFile ( "public.json", std::ios::in );
    json publicInfo = json::parse( jsonFile );

    std::vector<json> authStores;
    for (int i = 0; i<3; i++){
        std::ifstream authFile ( "Auth"+ std::to_string(i+1) +".json", std::ios::in );
        authStores.push_back(json::parse( authFile ));
    }
    //a1 and a2 from Auth1
    //a2 and a3 from Auth2
    //a1 and a3 from Auth3
    json attributes;
    attributes["T_1_1"] = authStores[0]["T_a1"];
    attributes["T_1_2"] = authStores[0]["T_a2"];
    attributes["T_2_1"] = authStores[1]["T_a1"];
    attributes["T_2_3"] = authStores[1]["T_a3"];
    attributes["T_3_2"] = authStores[2]["T_a2"];
    attributes["T_3_3"] = authStores[2]["T_a3"];

    pairing_t pairing;
    char param[1024];
    size_t count = fread(param, 1, 1024, fopen("a.param","r"));
    if (!count) pbc_die("input error");
    pairing_init_set_buf(pairing,param, count);

    element_t msg;
    element_init_GT(msg, pairing);
    //msg is where the symmetric key goes. <variable, keyvalue, key size>
    //NOTE: replace with random for real use. 
    element_from_hash(msg, (void*)"Hello", 5);

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
    mpz_set_str(side1, "C08A05030C15CBC957E60D0678BD4745", 16);    
    mpz_set_str(side2, "1367E9BBC427EC5B5C60E9C6B286C87B", 16);    

    element_snprint(s, 500, msg);
    std::string str;
    std::cout<<s<<std::endl;

    str = SplitString(s, '[')[1];
    str = SplitString(str, ']')[0];
    mpz_set_str(D1, SplitString(str, ',')[0].c_str(), 10);
    mpz_set_str(D2, SplitString(str, ',')[1].c_str(), 10);
    gmp_printf("Your elements are: %Zd and %Zd\n", D1, D2); 
    mpz_sub(D1, D1, side1);
    mpz_sub(D2, D2, side2);
    gmp_printf("Your Deltas are: %Zd and %Zd\n", D1, D2); 
    //////////////////Testing///////////////////////

    element_t Y, g2;
    element_init_GT(Y,pairing);
    element_init_G2(g2,pairing);

    convertFromString(Y, authStores[0]["Y_All"] );
    convertFromString(g2, publicInfo["g2"] );

    element_printf("%B\n", msg);

    json enc_msg = encrypt(msg, attributes, Y, g2, pairing);
    mpz_get_str(s, 10, D1);
    str = s;
    enc_msg["D1"] = str;
    mpz_get_str(s, 10, D2);
    str = s;
    enc_msg["D2"] = str;    
    std::string enc_string = enc_msg.dump();
    std::ofstream file("encrypt.json");
    file << enc_msg;        
    std::cout<<" All done, look good hopefully.\n";
    return 0;
}        
  