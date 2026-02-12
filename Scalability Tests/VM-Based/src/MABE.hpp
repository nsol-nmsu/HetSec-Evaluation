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
#include "MABE-util.hpp"

using json = nlohmann::json;

int generate(pbc_cm_t cm, void *data) {
    UNUSED_VAR(data);
    pbc_param_t param;
    pbc_info("gendparam: computing Hilbert polynomial and finding roots...");
    pbc_param_init_d_gen(param, cm);
    pbc_info("gendparam: bits in q = %zu\n", mpz_sizeinbase(cm->q, 2));
    FILE* paramFile = fopen("a.param", "w");
    pbc_param_out_str(paramFile, param);
    pbc_param_clear(param);    
    return 1;
}

json authSetup(int attributes,  pairing_t pairing, element_t g1, element_t g2, element_t e_g1g2){
    json authData;
    //MPK/MSK
    element_t v, Y, x, y;

    element_init_Zr(v,pairing);
    element_random(v);    
    authData["v"] = convertToString(v);

    element_init_GT(Y,pairing);
    element_pow_zn(Y, e_g1g2, v);    
    authData["Y"] = convertToString(Y);
    
    element_init_Zr(x,pairing);
    element_random(x);
    authData["x"] = convertToString(x);

    element_init_G1(y,pairing);
    element_pow_zn(y, g1, x);
    authData["y"] = convertToString(y);

    authData["attr_num"] = attributes;

    //Attr computation
    for ( int i = 0; i < attributes; i++ ){
        element_t t_a, T_a;

        element_init_Zr(t_a,pairing);
        element_random(t_a);
        authData["t_a"+std::to_string(i+1)] = convertToString(t_a);

        element_init_G2(T_a,pairing);
        element_pow_zn(T_a, g2, t_a);
        authData["T_a"+std::to_string(i+1)] = convertToString(T_a);
    }
    return authData;
}

//Lets make this non-dynamic    
std::pair<std::vector<json>, json> setup(int Auths, int attributes){
    //Setting EC
    int D = 9563;
    //int m = D % 4;

    pairing_t pairing;
    char param[1024];
    size_t count = fread(param, 1, 1230, fopen("a.param","r"));
    std::cout<<param<<std::endl;
    if (!count) pbc_die("input error");
    pairing_init_set_buf(pairing,param, count);

    element_t g1, g2, e_g1g2;
    element_init_G1(g1, pairing); element_init_G2(g2, pairing); element_init_GT(e_g1g2, pairing);    
    element_random(g1); element_random(g2);
    element_pairing(e_g1g2, g1,g2); 
    
    //Attributes 1,2,3,4, represented with ai where i is the index used in polynomials
    //#a1,a2,a3,a4

    std::vector<json> authStores;
    for ( int i = 0; i < Auths; i++ ){
        authStores.push_back( authSetup(attributes, pairing, g1, g2, e_g1g2) );
        authStores[i]["ID"] = i+1;
    }

    for ( int i = 0; i < Auths-1; i++ ){
        for ( int j = i; j < Auths; j++ ){
            element_t s;
            element_init_Zr(s,pairing);
            element_random(s);
            std::string s_ID = "s_"+std::to_string(i+1)+"-"+std::to_string(j+1);

            authStores[i][s_ID] = convertToString(s);
            authStores[j][s_ID] = convertToString(s);
        }
    }

    element_t Y_All, temp;
    element_init_GT(Y_All,pairing); element_init_GT(temp,pairing);    
    element_set1(Y_All);

    for ( int i = 0; i < Auths; i++ ){
        element_t Y_auth; 
        element_init_GT(Y_auth,pairing);
        convertFromString(Y_auth, authStores[i]["Y"]);
        element_mul(temp, Y_All, Y_auth); 
        element_set(Y_All, temp);
    }
    for ( int i = 0; i < Auths; i++ ){      
        authStores[i]["Y_All"] =  convertToString(Y_All);
    }

    //authorities also give NIZKP of v_k and x_k
    //TODO?

    //Auth stores
    //MSK = (x, (secrets), (private attributes))

    //system params published,
    //params = (Y_All, (y, public attributes))
    json publicInfo;
    //publicInfo["paring"] = convertToString(pairing);
    publicInfo["g1"] = convertToString(g1);
    publicInfo["g2"] = convertToString(g2);
    publicInfo["e_g1g2"] = convertToString(e_g1g2);
    return std::pair<std::vector<json>, json>(authStores, publicInfo);
}

json keyIssuing(json authStores,  pairing_t pairing, element_t g1){
    //USER SIGNUP
    json userInfo;

    //user GID
    element_t GID;
    element_init_Zr(GID,pairing);
    element_random(GID);
    userInfo["GID"] = convertToString(GID);

	json::iterator it_k = authStores.begin();
	while ( it_k !=  authStores.end() ) {
        json auth_k = it_k.value();
	    json::iterator it_j = authStores.begin();
	    while ( it_j !=  authStores.end() ) {
            json auth_j = it_j.value();

            if (auth_k["ID"] == auth_j["ID"]){
                it_j++;
                continue;
            }

            int k_ID =  auth_k["ID"]; int j_ID =  auth_j["ID"];
            std::string R_ID =  "R_" + std::to_string(k_ID) + "_" +  std::to_string(j_ID);

            element_t R_u;
            element_init_Zr(R_u,pairing);
            element_random(R_u);            
            userInfo[R_ID] = convertToString(R_u);

            /*****************************
            if  k > j  
            gamma = 1
            else gamma = -1
            alpha = gamma * R_k-j
            beta = s_k-j  
            ******************************/
            
            std::string D_ID =  "D_" + std::to_string(k_ID) + "-" +  std::to_string(j_ID);
            element_t PRF, temp_1, temp_2, s, x, y, D_k_j;
            element_init_G1 (y, pairing); element_init_Zr(s, pairing); element_init_Zr(x, pairing);

            if ( auth_k["ID"] > auth_j["ID"] ){
                std::string s_ID = "s_" + std::to_string(j_ID) + "-" +  std::to_string(k_ID);

                convertFromString(y, auth_j["y"]);
                convertFromString(x, auth_k["x"]);
                convertFromString(s, auth_k[s_ID]);

                //Preform PRF = y_j^(x_k * 1/(s_j-k + GID))
                element_init_Zr(temp_1, pairing);
                element_init_Zr(temp_2, pairing);
                element_add(temp_1,s,GID);
                element_div(temp_2,x,temp_1);

                element_init_G1(PRF,pairing);
                element_pow_zn(PRF, y, temp_1);
                element_clear(temp_1);
                element_clear(temp_2); 

                //Preform d = (g1^R_u) * PRF
                element_init_G1(D_k_j,pairing);
                element_init_G1(temp_1,pairing); 
                element_pow_zn(temp_1, g1, R_u);
                element_mul(D_k_j,temp_1,PRF); 
                element_clear(temp_1);
                userInfo[D_ID] = convertToString(D_k_j);
            }
            else {
                std::string s_ID = "s_" + std::to_string(k_ID) + "-" +  std::to_string(j_ID);
                convertFromString(y, auth_k["y"]);
                convertFromString(x, auth_j["x"]);
                convertFromString(s, auth_k[s_ID]);

                //Preform PRF = y_k^(x_j * 1/(s_j-k + GID))
                element_init_Zr(temp_1, pairing);
                element_init_Zr(temp_2, pairing);
                element_add(temp_1,s,GID);
                element_div(temp_2,x,temp_1);

                element_init_G1(PRF,pairing);
                element_pow_zn(PRF, y, temp_1);
                element_clear(temp_1);
                element_clear(temp_2);                 

                //Preform d = (g1^R_u) * 1/PRF
                element_init_G1(D_k_j,pairing);
                element_init_G1(temp_1,pairing); 
                element_pow_zn(temp_1, g1, R_u);
                element_div(D_k_j,temp_1,PRF); 
                element_clear(temp_1);                
                userInfo[D_ID] = convertToString(D_k_j);
            }
            it_j++;
        }
        it_k++;
    }
    //POLYNOMIAL CALCULATION setting d_k = 2
    //a1x + a0
    //stored as [a1, a0]
    //auth1
	it_k = authStores.begin();
	while ( it_k !=  authStores.end() ) {    
        json auth = it_k.value();
        element_t R_All, p_, v, coeff[2];
        element_init_Zr(v, pairing); element_init_Zr(p_, pairing);
        convertFromString(v,  auth["v"]);
        element_init_Zr(R_All, pairing);
        element_set0(R_All);

	    json::iterator it_j = authStores.begin();
	    while ( it_j !=  authStores.end() ) {      
            json otherAuth = it_j.value();
            if (otherAuth["ID"] == auth["ID"]){
                it_j++;
                continue;
            }
            int k_ID =  auth["ID"]; int j_ID =  otherAuth["ID"];
            std::string R_ID =  "R_" + std::to_string(k_ID) + "_" +  std::to_string(j_ID);

            element_t R_k_j, temp;
            element_init_Zr(R_k_j, pairing);
            convertFromString(R_k_j,  userInfo[R_ID]);
            element_init_Zr(temp, pairing);
            //Perform R_All += R_k_j
            element_add(temp,R_All,R_k_j);
            element_set(R_All, temp);
            element_clear(temp);                
            it_j++;
        }
        //Perform p_ = v - R_All
        element_sub(p_,v,R_All); 
        element_clear(v);
        element_clear(R_All);

        int ID = auth["ID"];
        std::string coeff_ID = "coeff_auth" + std::to_string(ID);

        // create coeff[2]
        element_init_Zr(coeff[0], pairing);
        element_random(coeff[0]);        
        element_init_Zr(coeff[1], pairing);
        element_set(coeff[1], p_);     

        std::vector<std::vector<unsigned char>> coeff_strings;
        coeff_strings.push_back(convertToString(coeff[0]));
        coeff_strings.push_back(convertToString(coeff[1]));

        userInfo[coeff_ID] = coeff_strings;
        it_k++;   
    }

    //auth setting S_k_i for user
	json::iterator it = authStores.begin();
	while ( it !=  authStores.end() ) {
        json auth = it.value();
        int  i = 0;
        while (i < auth["attr_num"]){
            i += 1;
            int authID =  auth["ID"];
            std::string S_ID = "S_" + std::to_string(authID) + "_" + std::to_string(i);
            std::string coeff_ID = "coeff_auth" + std::to_string(authID);
            std::string atrr_ID = "t_a"+std::to_string(i);
            element_t s, coeff[2], atrr, temp_1, temp_2, temp_3;
            element_init_Zr(coeff[0], pairing); element_init_Zr(coeff[1], pairing); element_init_Zr(atrr, pairing);
            convertFromString(coeff[0], userInfo[coeff_ID][0]);
            convertFromString(coeff[1], userInfo[coeff_ID][1]);
            convertFromString(atrr, auth[atrr_ID]);

            //perform: s = g1^(p(1, coeff) * (1 / t_))
            element_init_G1(s, pairing);
            element_init_Zr(temp_1, pairing); element_init_Zr(temp_2,pairing); element_init_Zr(temp_3,pairing);
            element_mul_si(temp_1,coeff[0],i);
            element_add(temp_2,temp_1,coeff[1]);    
            element_div(temp_3,temp_2,atrr);
            element_pow_zn(s, g1, temp_3); 
            element_clear(coeff[0]); element_clear(coeff[1]); element_clear(atrr);
            element_clear(temp_1); element_clear(temp_2); element_clear(temp_3);
            userInfo[S_ID] = convertToString(s);
        }
        it++;
    }

    element_t D_u, R_u;
    element_init_G1(D_u, pairing);
    element_init_Zr(R_u, pairing);    
    element_set1(D_u);
    element_set0(R_u);

	it_k = authStores.begin();
	while ( it_k !=  authStores.end() ) { 
        json auth_k = it_k.value();
	    json::iterator it_j = authStores.begin();
	    while ( it_j !=  authStores.end() ) {   
            json auth_j = it_j.value();
            if (auth_k["ID"] == auth_j["ID"]){
                it_j++;
                continue;
            }
            int k_ID = auth_k["ID"];
            int j_ID = auth_j["ID"];
            std::string D_ID =  "D_" + std::to_string(k_ID) + "-" +  std::to_string(j_ID);
            element_t temp, D_k_j, R_k_j;
            element_init_G1(temp, pairing); element_init_G1(D_k_j, pairing);
            convertFromString(D_k_j, userInfo[D_ID]);
            element_mul(temp, D_u, D_k_j);
            element_set(D_u, temp);
            element_clear(D_k_j);                
            element_clear(temp);                

            std::string R_ID =  "R_" + std::to_string(k_ID) + "_" +  std::to_string(j_ID);
            element_init_Zr(temp, pairing); element_init_Zr(R_k_j, pairing);    
            convertFromString(R_k_j, userInfo[R_ID]); 

            element_add(temp, R_u, R_k_j);
            element_set(R_u, temp);

            element_clear(R_k_j);                
            element_clear(temp);                
            it_j++;
        }
        it_k++;
    }

    element_t test_D_u;
    element_init_G1(test_D_u, pairing);
    element_pow_zn(test_D_u, g1, R_u);
    if (element_cmp(D_u,test_D_u) == 0) {
        printf("D_u check succeeded\n");
    }
    else { 
        printf("D_u check failed\n"); 
    }
    userInfo["D_u"] = convertToString(D_u);
    return userInfo;
}

//Attriubes shhould be dictionary with ID of attribute as key like T_<auth ID>_<attribute ID>
//NOTE: Group seems to be replaced by pairing
json encrypt(element_t msg, json attributes, element_t Y, element_t g2, pairing_t pairing){

    element_t E_0, E_1, s;
    element_init_Zr(s,pairing);
    element_random(s);

    json enc_msg;
    element_t temp_1;

    //Save "s" value
    enc_msg["s"] = convertToString(s);

    //Preform E_0 calculation
    element_init_GT(E_0, pairing);
    element_init_GT(temp_1, pairing);
    element_pow_zn(temp_1, Y, s);
    element_mul(E_0, msg, temp_1);
    element_clear(temp_1);
    //Save Result
    enc_msg["E_0"] = convertToString(E_0);

    //Preform E_1 calculation
    element_init_G2(E_1, pairing);
    element_pow_zn(E_1, g2, s);   
    //Save Result
    enc_msg["E_1"] = convertToString(E_1);

	json::iterator it = attributes.begin();
	while ( it !=  attributes.end() ) {
        //Create identifier using attribute name
        std::string C_ID = "C_" + SplitString(it.key(), '_')[1] + "_" +  SplitString(it.key(), '_')[2];

        //Read Attriubte
        element_t attribute;
        element_init_G2(attribute, pairing);
        convertFromString(attribute, it.value());

        //Compute C_k_i and store in temp
        element_t temp;
        element_init_G2(temp, pairing);
        element_pow_zn(temp, attribute, s);

        //Store result into json dictionary
        enc_msg[C_ID] = convertToString(temp);

        it++;
    }
    return enc_msg;
}

void decrypt( json enc_msg, json userInfo, pairing_t pairing, element_t g1, element_t g2, element_t e_g1g2, element_t msg, element_t decrypted_msg){
    element_t temp_1, temp_2, temp_3, temp_P;

    //User decrypting the msg
    element_t s;
    element_init_Zr(s, pairing);
    convertFromString(s, enc_msg["s"]);

    //a1,a2 attr from auth1
    std::unordered_map<std::string, element_t> authList;
    std::unordered_map<int, std::vector<std::string>> authRecord;
	json::iterator it = enc_msg.begin();

	while ( it !=  enc_msg.end() ) {
        std::vector<std::string> C_ID = SplitString( it.key(), '_');
        if ( C_ID[0] != "C" ) {
            it++;
            continue;
        }
        std::string auth = C_ID[1], attribute = C_ID[2];
        std::string S_ID = "S_"+auth+"_"+attribute;
        std::string A_ID = "A_"+auth+"_"+attribute;
        authRecord[std::stoi(auth)].push_back(A_ID);

        if ( userInfo.find(S_ID) == userInfo.end() )
            return;
        
        element_t S_Temp, C_Temp, auth_pair;
        element_init_G1(S_Temp, pairing); element_init_G2(C_Temp, pairing);
        convertFromString(S_Temp, userInfo[S_ID]);
        convertFromString(C_Temp,enc_msg[it.key()]);

        element_init_GT(authList[A_ID], pairing);
        element_pairing(authList[A_ID], S_Temp, C_Temp);         

        std::string coeff_ID = "coeff_auth" + auth;

        element_t coeff[2];
        element_init_Zr(coeff[0], pairing); element_init_Zr(coeff[1], pairing); 
        convertFromString(coeff[0], userInfo[coeff_ID][0]);
        convertFromString(coeff[1], userInfo[coeff_ID][1]);

        element_t temp_auth;
        element_init_Zr(temp_1, pairing); 
        element_init_Zr(temp_2, pairing);
        element_init_Zr(temp_3, pairing);
        element_init_GT(temp_auth, pairing);
        element_mul_si(temp_1,coeff[0],  std::stoi(attribute));
        element_add(temp_2,temp_1,coeff[1]);
        element_mul(temp_3, temp_2, s);
        element_pow_zn(temp_auth, e_g1g2, temp_3); 
        
        if ( element_cmp( authList[A_ID], temp_auth ) == 0) {
            std::cout<<A_ID <<" auth" << auth <<" attr"<< attribute <<" dec 1 (a) step Successful \n";
        }
        else {
            std::cout<<A_ID <<" auth" << auth <<" attr"<< attribute <<" dec 1 (a) step failed \n";
        }
        element_clear(temp_1); element_clear(temp_2); element_clear(temp_3); element_clear(temp_auth);
        element_clear(S_Temp); element_clear(C_Temp);
        it++;
    }

    std::unordered_map<std::string, element_t> interpolation_coeffients;
    for (auto i = authList.begin(); i != authList.end(); i++) {
        std::string A_ID = i->first;
        std::string authi = SplitString( A_ID, '_')[1];
        std::string attributei = SplitString( A_ID, '_')[2];
        if ( interpolation_coeffients.find(A_ID)  == interpolation_coeffients.end() )
            element_init_Zr(interpolation_coeffients[A_ID], pairing);
            element_set1(interpolation_coeffients[A_ID]);
        for (auto j = authList.begin(); j != authList.end(); j++) {
            std::string authj = SplitString( j->first, '_')[1];
            std::string attributej = SplitString( j->first, '_')[2];
        
            if (attributei == attributej || authi != authj)
                continue;

            element_t int_coeff, ai, aj, zero, temp;

            element_init_Zr(int_coeff, pairing); element_init_Zr(ai, pairing), element_init_Zr(aj, pairing),  element_init_Zr(zero, pairing); 
            element_init_Zr(temp, pairing), element_init_Zr(temp_1, pairing), element_init_Zr(temp_2, pairing);
            element_set_si(ai, std::stoi(attributei) ); element_set_si(aj, std::stoi(attributej)); element_set0(zero);

            element_sub(temp_1, zero, aj); element_sub(temp_2, ai, aj);
            element_div(int_coeff, temp_1, temp_2);
            element_mul(temp, int_coeff, interpolation_coeffients[A_ID]);
            element_set(interpolation_coeffients[A_ID], temp);
            element_clear(temp_1); element_clear(temp_2);
        }
    }

    element_t Q;
    element_init_GT(Q, pairing);
    element_set1(Q);    
    for (auto i = authRecord.begin(); i != authRecord.end(); i++) {
        element_t P_i, temp_1, temp_2, temp_3, temp_P;
        element_init_GT(P_i, pairing);
        element_set1(P_i);
        for (int j = 0; j < i->second.size(); j++ ){
            element_init_GT(temp_1, pairing); element_init_GT(temp_2, pairing);
            std::string A_ID = i->second[j];        

            element_pow_zn(temp_1, authList[A_ID], interpolation_coeffients[A_ID]); 
            element_mul(temp_2, P_i, temp_1); 
            element_set(P_i, temp_2);
            element_clear(temp_1); element_clear(temp_2);
        }
        element_init_Zr(temp_1, pairing); element_init_Zr(temp_2, pairing); element_init_Zr(temp_3, pairing); element_init_GT(temp_P, pairing);
        element_t coeff[2];
        element_init_Zr(coeff[0], pairing); element_init_Zr(coeff[1], pairing); 
        std::string coeffID = "coeff_auth" + std::to_string(i->first);
        convertFromString(coeff[0], userInfo[coeffID][0]);
        convertFromString(coeff[1], userInfo[coeffID][1]);

        element_mul_si(temp_1,coeff[0],0);
        element_add(temp_2,temp_1,coeff[1]);
        element_mul(temp_3, temp_2, s);
        element_pow_zn(temp_P, e_g1g2, temp_3);
        if (element_cmp(P_i, temp_P) == 0) {
            std::cout << "auth" << i->first << " dec 1(b) Successful\n";
        }
        else {
            std::cout << "auth" << i->first << " dec 1(b) failed\n";
        }
        element_clear(temp_1); element_clear(temp_2); element_clear(temp_3); element_clear(temp_P);  

        element_t temp;
        element_init_GT(temp, pairing);
        element_mul(temp, Q, P_i);
        element_set(Q, temp);
        element_clear(temp);        
    }

    element_t dec_step3, temp;
    element_init_GT(temp, pairing); element_init_GT(dec_step3, pairing);

    element_t D_u, E_0, E_1;
    element_init_G1(D_u, pairing); element_init_GT(E_0, pairing); element_init_G2(E_1, pairing);
    convertFromString(D_u, userInfo["D_u"]);
    convertFromString(E_0, enc_msg["E_0"]);     
    convertFromString(E_1, enc_msg["E_1"]);

    
    element_pairing(temp, D_u, E_1);
    element_mul(dec_step3, temp, Q);

    //decrypted_msg = E_0 * (1 / dec_step3)
    element_div(decrypted_msg, E_0, dec_step3); 
    element_clear(temp_1);


    //Check if we are debug testing decryption, return if not.
    element_t zero;
    element_init_GT(zero, pairing);
    element_set0(zero);
    if(element_cmp(zero,msg) == 0)
        return;

    if (element_cmp(msg,decrypted_msg) == 0) {
        printf("Message Decryption Successful\n");
    }
    else { 
        printf("Message Decryption Failed\n"); 
    }
    return;
}