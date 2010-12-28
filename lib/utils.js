/* Taken from Cast */
/*
 * Licensed to Cloudkick, Inc ('Cloudkick') under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * Cloudkick licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
/**
 * Generate a random string of upper lower case letters and decimal digits.
 *
 * @param {Number} len  The length of the string to return;.
 * @return {String} Random string.
 */
exports.randstr = function(len) {
  var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

  function getRandomInt(min, max)
  {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }

  var r = [];
  for (var x = 0; x < len; x++) {
    r.push(chars[getRandomInt(0, chars.length)]);
  }

  return r.join('');
};
