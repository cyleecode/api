import { verify } from '@noble/ed25519'
import algosdk from 'algosdk'
import { TokenInvalidError } from '../error/token-invalid-error.js'
import { day1, minutes30 } from '../utils/constants.js'
import { authenticatePath } from '../utils/auth-path.js'
import { TokenExpiredError } from '../error/token-expired-error.js'

export default async function authHandler(ctx, next) {
    await next()
    //check if path is allow for non auth
    if (authenticatePath.includes(ctx.request.url)) {
        const accountId = ctx.headers?.walletaddress
        const token = ctx.headers?.authorization?.split(' ')
        if (token?.length !== 2) throw new TokenInvalidError()

        //converting the base64 encoded tx back to binary data
        const decodeToken = new Uint8Array(Buffer.from(token[1], 'base64'))
        //getting a SignedTransaction object from the array buffer
        const decodedTx = algosdk.decodeSignedTransaction(decodeToken)

        //auth tx whose params we'll check
        const toCheck = decodedTx.txn

        // get the signature from the signed transaction
        const signature = decodedTx.sig

        // parse the note back to utf-8
        const note = new TextDecoder().decode(toCheck.note)
        const decodedNote = note.split(' ')
        const tokenAccountId = decodedNote[2]
        // "from" and "to" are distincts ArrayBuffers,
        // comparing them directly would always return false.
        // We therefore convert them back to base32 for comparison.
        const from = algosdk.encodeAddress(toCheck.from.publicKey)
        const to = algosdk.encodeAddress(toCheck.to.publicKey)
        // Guard clause to make sure the token has not expired.
        // We also check the token expiration is not too far out, which would be a red flag.
        if (Number(decodedNote[1]) < Date.now() || Number(decodedNote[1]) > Date.now() + day1 + minutes30) {
            throw new TokenExpiredError()
        }

        // We check if the params match the ones we set in the front-end
        if (
            toCheck.firstRound === 10 &&
            toCheck.lastRound === 10 &&
            decodedNote[0] === process.env.AUTH_SECRET &&
            from === to &&
            // It is crucial to verify this or an attacker could sign
            // their own valid token and log into any account!
            from === accountId &&
            tokenAccountId === accountId
        ) {
            // verify signature and return if it succeeds
            const verified = await verify(signature, toCheck.bytesToSign(), toCheck.from.publicKey)
            if (verified) {
                return
            }
        }
        throw new TokenInvalidError()
    }
}
