import * as dayjs from "dayjs";
import * as ed from '@noble/ed25519';
import {sign} from "@noble/ed25519";

export class License {
    product: string
    domain: string
    machine_id: string
    expire_at: string
    signature: string

    Serialize() {
        let str = "p:" + this.product + "\n"
        str += "d:" + this.domain + "\n"
        str += "m:" + this.machine_id + "\n"
        str += "e:" + dayjs(this.expire_at).format("YYYY-MM-DD HH:mm:ss")
        return str
    }

    Sign(key: string) {

        let msg = this.Serialize()

        let kk = ed.etc.hexToBytes(key)

        let sign = ed.sign(msg, key)

        this.signature = ed.etc.bytesToHex(sign)
    }

    Verify(key: string) {

        let msg = this.Serialize()

        let sign = ed.etc.hexToBytes(this.signature)

        let kk = ed.etc.hexToBytes(key)

        return ed.verify(sign, msg, key)
    }
}

