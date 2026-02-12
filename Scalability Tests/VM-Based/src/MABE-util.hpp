#include <fstream>
#include <iomanip>
#include <iostream>
#include "pbc.h"

using json = nlohmann::json;

std::vector<std::string> SplitString( std::string strLine, char delimiter ) {
   std::string str = strLine;
   std::vector<std::string> result;
   uint32_t i =0;
   std::string buildStr = "";

   for ( i = 0; i<str.size(); i++) {
      if ( str[i]== delimiter ) {
         result.push_back( buildStr );
	 buildStr = "";
      }
      else {
   	      buildStr += str[i];
      }
   }

   if(buildStr!="")
      result.push_back( buildStr );

   return result;
};

std::vector<unsigned char> convertToString(element_t variable){
   int n = element_length_in_bytes(variable);
   unsigned char* bytes = (unsigned char *) malloc(n);
   n = element_to_bytes(bytes, variable);
   std::vector<unsigned char> str;
   for (int i = 0; i < n; ++i)
   {
      //str += " ";
      str.push_back(bytes[i]);
   }   
   return str;   
}

void convertFromString(element_t var, std::vector<unsigned char> charArray){
   std::string str(charArray.begin(), charArray.end());   
   size_t n = sizeof( str );
   unsigned char* bytes = (unsigned char *) malloc( str.size() ); 
   for (int i = 0; i < str.size(); ++i)
   {
      bytes[i] = str[i];
   }
   element_from_bytes(var, bytes);
   return;
}
