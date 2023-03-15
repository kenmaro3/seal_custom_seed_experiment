#ifndef BASE64_HPP_20100908_
#define BASE64_HPP_20100908_

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
# pragma once
#endif


#include <string>
#include <vector>


namespace algorithm {
    bool encode_base64(const std::vector<unsigned char>& src, std::string& dst);
    bool decode_base64(const std::string& src, std::vector<unsigned char>& dst);
}


#endif
