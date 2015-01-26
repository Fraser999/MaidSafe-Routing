/*  Copyright 2014 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#ifndef MAIDSAFE_ROUTING_MESSAGES_GET_DATA_RESPONSE_H_
#define MAIDSAFE_ROUTING_MESSAGES_GET_DATA_RESPONSE_H_
#include <vector>
#include "boost/optional.hpp"

#include "maidsafe/routing/types.h"

namespace maidsafe {

namespace routing {

struct GetDataResponse {
  GetDataResponse() = default;
  ~GetDataResponse() = default;

  template <typename T, typename U, typename V>
  GetDataResponse(T&& key, U&& data, V&& relay_node)
      : key{std::forward<T>(key)},
        data{std::forward<U>(data)},
        relay_node{std::forward<U>(relay_node)} {}

  template <typename T, typename U>
  GetDataResponse(T&& key, U&& data)
      : key{std::forward<T>(key)}, data{std::forward<U>(data)} {}

  GetDataResponse(GetDataResponse&& other) MAIDSAFE_NOEXCEPT : key{std::move(other.key)},
                                                               data{std::move(other.data)} {}

  GetDataResponse& operator=(GetDataResponse&& other) MAIDSAFE_NOEXCEPT {
    key = std::move(other.key);
    data = std::move(other.data);
    return *this;
  }

  GetDataResponse(const GetDataResponse&) = delete;
  GetDataResponse& operator=(const GetDataResponse&) = delete;

  void operator()() {}

  template <typename Archive>
  void serialize(Archive& archive) {
    archive(key, data, relay_node);
  }

  Address key;
  std::vector<byte> data;
  boost::optional<Address> relay_node;
};

}  // namespace routing

}  // namespace maidsafe

#endif  // MAIDSAFE_ROUTING_MESSAGES_GET_DATA_RESPONSE_H_
