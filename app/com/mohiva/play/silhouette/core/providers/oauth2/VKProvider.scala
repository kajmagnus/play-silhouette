/**
 * Original work: SecureSocial (https://github.com/jaliss/securesocial)
 * Copyright 2013 Jorge Aliss (jaliss at gmail dot com) - twitter: @jaliss
 *
 * Derivative work: Silhouette (https://github.com/mohiva/play-silhouette)
 * Modifications Copyright 2014 Mohiva Organisation (license at mohiva dot com)
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
package com.mohiva.play.silhouette.core.providers.oauth2

import scala.concurrent.Future
import play.api.libs.json.{ JsValue, JsObject }
import play.api.libs.concurrent.Execution.Implicits._
import com.mohiva.play.silhouette.core.LoginInfo
import com.mohiva.play.silhouette.core.providers._
import com.mohiva.play.silhouette.core.utils.{ HTTPLayer, CacheLayer }
import com.mohiva.play.silhouette.core.exceptions.AuthenticationException
import VKProvider._

/**
 * A Vk OAuth 2 provider.
 *
 * @param applicationSecret The value of your Play app's application.secret config value
 * @param httpLayer The HTTP layer implementation.
 * @param settings The provider settings.
 *
 * @see http://vk.com/dev/auth_sites
 * @see http://vk.com/dev/api_requests
 * @see http://vk.com/pages.php?o=-1&p=getProfiles
 */
abstract class VKProvider(applicationSecret: String, httpLayer: HTTPLayer, settings: OAuth2Settings)
    extends OAuth2Provider(applicationSecret, httpLayer, settings) {

  /**
   * Gets the provider ID.
   *
   * @return The provider ID.
   */
  def id = Vk

  /**
   * Gets the API URL to retrieve the profile data.
   *
   * @return The API URL to retrieve the profile data.
   */
  protected def profileAPI = API

  /**
   * Builds the social profile.
   *
   * @param authInfo The auth info received from the provider.
   * @return On success the build social profile, otherwise a failure.
   */
  protected def buildProfile(authInfo: OAuth2Info): Future[Profile] = {
    httpLayer.url(profileAPI.format(authInfo.accessToken)).get().flatMap { response =>
      val json = response.json
      (json \ "error").asOpt[JsObject] match {
        case Some(error) =>
          val errorCode = (error \ "error_code").as[Int]
          val errorMsg = (error \ "error_msg").as[String]

          throw new AuthenticationException(SpecifiedProfileError.format(id, errorCode, errorMsg))
        case _ => parseProfile(parser(authInfo), json).asFuture
      }
    }
  }

  /**
   * Defines the parser which parses the most common profile supported by Silhouette.
   *
   * @return The parser which parses the most common profile supported by Silhouette.
   */
  protected def parser: Parser = (authInfo: OAuth2Info) => (json: JsValue) => {
    val response = (json \ "response").apply(0)
    val userId = (response \ "uid").as[Long]
    val firstName = (response \ "first_name").asOpt[String]
    val lastName = (response \ "last_name").asOpt[String]
    val avatarURL = (response \ "photo").asOpt[String]

    CommonSocialProfile(
      loginInfo = LoginInfo(id, userId.toString),
      authInfo = authInfo,
      firstName = firstName,
      lastName = lastName,
      avatarURL = avatarURL)
  }
}

/**
 * The companion object.
 */
object VKProvider {

  /**
   * The error messages.
   */
  val SpecifiedProfileError = "[Silhouette][%s] Error retrieving profile information. Error code: %s, message: %s"

  /**
   * The VK constants.
   */
  val Vk = "vk"
  val API = "https://api.vk.com/method/getProfiles?fields=uid,first_name,last_name,photo&access_token=%s"

  /**
   * Creates an instance of the provider.
   *
   * @param applicationSecret The value of your Play app's application.secret config value
   * @param httpLayer The HTTP layer implementation.
   * @param settings The provider settings.
   * @return An instance of this provider.
   */
  def apply(applicationSecret: String, httpLayer: HTTPLayer, settings: OAuth2Settings) = {
    new VKProvider(applicationSecret, httpLayer, settings) with CommonSocialProfileBuilder[OAuth2Info]
  }
}
