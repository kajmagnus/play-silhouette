/**
 * Copyright 2014 Mohiva Organisation (license at mohiva dot com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.mohiva.play.silhouette.core.providers

import java.{ security => js }
import org.apache.commons.codec.{ binary => acb }

/**
 * Signs the OAuth2 'state' parameter so it can be verified it has not been
 * tampered with. This protects against CSRF attacks.
 */
object StateSigner {

  private val Separator = '~'

  private val randomGenerator = new java.security.SecureRandom() // thread safe

  private def mdSha1 = js.MessageDigest.getInstance("SHA-1") // not thread safe

  /**
   * Hashes the specified text using SHA1 and encodes in URL safe Base64.
   */
  private def hash(text: String): String =
    acb.Base64.encodeBase64URLSafeString(mdSha1.digest(text.getBytes("UTF-8")))

  def signState(applicationSecret: String, state: String): String = {
    // A random string, characters 0..9, a..z.
    val nonce = new java.math.BigInteger(130, randomGenerator).toString(36)
    val nonceAndState = s"$nonce$Separator$state"
    val signature = hash(s"$applicationSecret$Separator$nonceAndState")
    s"$signature$Separator$nonceAndState"
  }

  def checkSignedState(applicationSecret: String, signedState: String): String = {
    val (signatureInRequest, separatorNonceAndState) = signedState.span(_ != Separator)
    val (nonce, separatorAndState) = separatorNonceAndState.drop(1).span(_ != Separator)
    val correctSignature = hash(s"$applicationSecret$separatorNonceAndState")
    if (correctSignature != signatureInRequest) {
      sys.error(s"bad signature in: $signedState, should be: $correctSignature")
      // something like: throw new AuthenticationException(StateIsNotEqual.format(id))
    }
    val state = separatorAndState.drop(1)
    state
  }

}

