#ifndef UAL_INCLUDE_ATTESTATION_COMMON_PROTOBUF_H_
#define UAL_INCLUDE_ATTESTATION_COMMON_PROTOBUF_H_

#include <string>

#include "google/protobuf/util/json_util.h"  // for message to json

#include "attestation/common/error.h"
#include "attestation/common/log.h"

#define PB_PARSE(pbmsg, pbstr)                                  \
  do {                                                          \
    if (!(pbmsg).ParseFromString(pbstr)) {                      \
      ELOG_ERROR("Fail to parse protobuf message: %s", #pbmsg); \
      return TEE_ERROR_PROTOBUF_PARSE;                          \
    }                                                           \
  } while (0)

#define PB_SERIALIZE(pbmsg, p_pbstr)                                \
  do {                                                              \
    if (!(pbmsg).SerializeToString(p_pbstr)) {                      \
      ELOG_ERROR("Fail to serialize protobuf message: %s", #pbmsg); \
      return TEE_ERROR_PROTOBUF_SERIALIZE;                          \
    }                                                               \
  } while (0)

// Use p_jsonstr_once to avoid the side effort of
// the reference to p_jsonstr more than one time
// for example, useing pbmsg.add_xxx() as p_jsonstr
#define PB2JSON(pbmsg, p_jsonstr)                                   \
  do {                                                              \
    using google::protobuf::util::MessageToJsonString;              \
    std::string* p_jsonstr_once = (p_jsonstr);                      \
    (p_jsonstr_once)->clear();                                      \
    if (!MessageToJsonString((pbmsg), (p_jsonstr_once)).ok()) {     \
      ELOG_ERROR("Protobuf message %s to json str failed", #pbmsg); \
      return TEE_ERROR_PROTOBUF_SERIALIZE_JSON;                     \
    }                                                               \
  } while (0)

#define JSON2PB(jsonstr, p_pbmsg)                                 \
  do {                                                            \
    using google::protobuf::util::JsonStringToMessage;            \
    if (!JsonStringToMessage((jsonstr), (p_pbmsg)).ok()) {        \
      ELOG_ERROR("Json str to protobuf msg %s failed", #p_pbmsg); \
      return TEE_ERROR_PROTOBUF_PARSE_JSON;                       \
    }                                                             \
  } while (0)

#endif  // UAL_INCLUDE_ATTESTATION_COMMON_PROTOBUF_H_
