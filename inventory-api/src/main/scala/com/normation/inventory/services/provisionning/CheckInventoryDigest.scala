/*
*************************************************************************************
* Copyright 2015 Normation SAS
*************************************************************************************
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Affero General Public License as
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* In accordance with the terms of section 7 (7. Additional Terms.) of
* the GNU Affero GPL v3, the copyright holders add the following
* Additional permissions:
* Notwithstanding to the terms of section 5 (5. Conveying Modified Source
* Versions) and 6 (6. Conveying Non-Source Forms.) of the GNU Affero GPL v3
* licence, when you create a Related Module, this Related Module is
* not considered as a part of the work and may be distributed under the
* license agreement of your choice.
* A "Related Module" means a set of sources files including their
* documentation that, without modification of the Source Code, enables
* supplementary functions or services in addition to those offered by
* the Software.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/agpl.html>.
*
*************************************************************************************
*/

package com.normation.inventory.services.provisioning

import java.io.InputStream
import net.liftweb.common._
import scala.io.Source
import java.util.Properties



/**
 * We are using a simple date structure that handle the digest file
 * version and content
 */
sealed trait InventoryDigest

final case class InventoryDigestV1(
    algorithm: String
  , digest   : String
) extends InventoryDigest

/**
 * This trait allow to check digest file for an inventory.
 * It handles the parsing of the .sig file.
 * The actual checking is done in CheckInventoryDigest
 */
trait ParseInventoryDigestFile {
  def parse(is: InputStream): Box[InventoryDigest]
}

/**
 * Parse a V1 file format:
 * -------
 * header=rudder-signature-v1
 * algorithm=${HASH}
 * digest=${SIGNATURE}
 * -------
 */
class ParseInventoryDigestFileV1 extends ParseInventoryDigestFile {
  def parse(is: InputStream): Box[InventoryDigest] = {

    val properties = new Properties()

    for {
      loaded  <- try {
                   import scala.collection.JavaConverters._
                   properties.load(is)
                   Full(System.getProperties().asInstanceOf[java.util.Map[String, String]].asScala.toMap)
                 } catch {
                   case ex: Exception => Failure("Failed to load properties for the signature file", Full(ex), Empty)
                 }
      //check version
      v_ok    <- Box((loaded.get("header").filter( _.trim.toLowerCase == "rudder-signature-v1" )))
      algo    <- Box(loaded.get("algorithm").map( _.trim.toLowerCase))
      algo_ok <- if(algo == "sha512") {  // in v1, we only accpet sha512
                   Full("ok")
                 } else {
                   Failure(s"The algorithm '${algo}' contains in the digest file is not authorized, only 'sha512' is.")
                 }
      digest  <- Box(loaded.get("digest").map( _.trim))
    } yield {
      InventoryDigestV1("","")
    }
  }
}

trait CheckInventoryDigest {


  /**
   * Here, we want to calculate the digest. The good library for that is most likelly
   * bouncy castle: https://www.bouncycastle.org/
   */
  def check(pubkey: String, digest: InventoryDigest, is: InputStream): Box[Boolean]

}

/**
 * Big question : how do we get the key ?
 *
 *
 * It makes no sense to take the key from the inventory, because it would be quite
 * easy to temper the inventory, add its own key in it, and temper the sig file.
 * ( or perhpas not, because https all the way, so no man in the middle attack ?)
 *
 * BUT we still need to look in the inventory at least for the first time, because
 * before the first inventory acceptation, we don't have the key at all.
 *
 * We could go look in cfengine store.
 *
 * The general logic that we want to have is:
 * - for existing nodes and inventories pre-3.1, they can continue to work without a key until the first time
 *   a ".sign" file is sent. From that time on, they are like v3.1 nodes.
 *   ===> we need to store somewhere the checked used. I'm not sure where: the "node" entry for the
 *   inventory may not exists already. So perhaps in the "node inventory" part.
 *
 * - new nodes must have a .sign file. We use the key in the inventory to check
 *   that the inventory file correspond to the digest.
 * - v3.1 nodes must always send inventory + sign file. We check that the digest of the
 *   inventory is ok with the key, and also that the key didn't changed
 *   (NOTE: what to do if so ? We still want to authorize key legal key change... So just a
 *   warn log ?).
 */
trait GetKey {


}

