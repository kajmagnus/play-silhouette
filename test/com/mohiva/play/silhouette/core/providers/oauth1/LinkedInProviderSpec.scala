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
package com.mohiva.play.silhouette.core.providers.oauth1

import test.Helper
import java.util.UUID
import play.api.libs.ws.{ WSResponse, WSRequestHolder }
import play.api.test.{ FakeRequest, WithApplication }
import scala.concurrent.Future
import com.mohiva.play.silhouette.core.LoginInfo
import com.mohiva.play.silhouette.core.providers._
import com.mohiva.play.silhouette.core.exceptions.AuthenticationException
import SocialProfileBuilder._
import LinkedInProvider._
import OAuth1Provider._

/**
 * Test case for the [[com.mohiva.play.silhouette.core.providers.oauth1.LinkedInProvider]] class.
 */
class LinkedInProviderSpec extends OAuth1ProviderSpec {

  "The authenticate method" should {
    "fail with AuthenticationException if API returns error" in new WithApplication with Context {
      val cacheID = UUID.randomUUID().toString
      val requestHolder = mock[WSRequestHolder]
      val response = mock[WSResponse]
      implicit val req = FakeRequest(GET, "?" + OAuthVerifier + "=my.verifier").withSession(CacheKey -> cacheID)
      cacheLayer.get[OAuth1Info](cacheID) returns Future.successful(Some(oAuthInfo))
      oAuthService.retrieveAccessToken(oAuthInfo, "my.verifier") returns Future.successful(oAuthInfo)
      requestHolder.sign(any) returns requestHolder
      requestHolder.get() returns Future.successful(response)
      response.json returns Helper.loadJson("providers/oauth1/linkedin.error.json")
      httpLayer.url(API) returns requestHolder

      failed[AuthenticationException](provider.authenticate()) {
        case e => e.getMessage must equalTo(SpecifiedProfileError.format(
          provider.id,
          0,
          Some("Unknown authentication scheme"),
          Some("LY860UAC5U"),
          Some(401),
          Some(1390421660154L)))
      }

      there was one(cacheLayer).remove(cacheID)
    }

    "fail with AuthenticationException if an unexpected error occurred" in new WithApplication with Context {
      val cacheID = UUID.randomUUID().toString
      val requestHolder = mock[WSRequestHolder]
      val response = mock[WSResponse]
      implicit val req = FakeRequest(GET, "?" + OAuthVerifier + "=my.verifier").withSession(CacheKey -> cacheID)
      cacheLayer.get[OAuth1Info](cacheID) returns Future.successful(Some(oAuthInfo))
      oAuthService.retrieveAccessToken(oAuthInfo, "my.verifier") returns Future.successful(oAuthInfo)
      requestHolder.sign(any) returns requestHolder
      requestHolder.get() returns Future.successful(response)
      response.json throws new RuntimeException("")
      httpLayer.url(API) returns requestHolder

      failed[AuthenticationException](provider.authenticate()) {
        case e => e.getMessage must equalTo(UnspecifiedProfileError.format(provider.id))
      }

      there was one(cacheLayer).remove(cacheID)
    }

    "return the social profile" in new WithApplication with Context {
      val cacheID = UUID.randomUUID().toString
      val requestHolder = mock[WSRequestHolder]
      val response = mock[WSResponse]
      implicit val req = FakeRequest(GET, "?" + OAuthVerifier + "=my.verifier").withSession(CacheKey -> cacheID)
      cacheLayer.get[OAuth1Info](cacheID) returns Future.successful(Some(oAuthInfo))
      oAuthService.retrieveAccessToken(oAuthInfo, "my.verifier") returns Future.successful(oAuthInfo)
      requestHolder.sign(any) returns requestHolder
      requestHolder.get() returns Future.successful(response)
      response.json returns Helper.loadJson("providers/oauth1/linkedin.success.json")
      httpLayer.url(API) returns requestHolder

      profile(provider.authenticate()) {
        case p =>
          p must be equalTo new CommonSocialProfile(
            loginInfo = LoginInfo(provider.id, "NhZXBl_O6f"),
            authInfo = oAuthInfo,
            firstName = Some("Apollonia"),
            lastName = Some("Vanova"),
            fullName = Some("Apollonia Vanova"),
            email = Some("apollonia.vanova@watchmen.com"),
            avatarURL = Some("http://media.linkedin.com/mpr/mprx/0_fsPnURNRhLhk_Ue2fjKLUZkB2FL6TOe2S4bdUZz61GA9Ysxu_y_sz4THGW5JGJWhaMleN0F61-Dg")
          )
      }

      there was one(cacheLayer).remove(cacheID)
    }
  }

  /**
   * Defines the context for the abstract OAuth1 provider spec.
   *
   * @return The Context to use for the abstract OAuth1 provider spec.
   */
  override protected def context: OAuth1ProviderSpecContext = new Context {}

  /**
   * The context.
   */
  trait Context extends OAuth1ProviderSpecContext {

    /**
     * The OAuth1 settings.
     */
    lazy val oAuthSettings = OAuth1Settings(
      requestTokenURL = "https://api.linkedin.com/uas/oauth/requestToken",
      accessTokenURL = "https://api.linkedin.com/uas/oauth/accessToken",
      authorizationURL = "https://api.linkedin.com/uas/oauth/authenticate",
      callbackURL = "https://www.mohiva.com",
      consumerKey = "my.consumer.key",
      consumerSecret = "my.consumer.secret")

    /**
     * The provider to test.
     */
    lazy val provider = LinkedInProvider(cacheLayer, httpLayer, oAuthService, oAuthSettings)
  }
}
