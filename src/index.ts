import dayjs from "dayjs";
import * as ed from '@noble/ed25519';

export class License {
    product: string = ''
    domain: string = ''
    machine_id: string = ''
    expire_at: string = ''
    signature: string = ''

    Stringify() {
        let str = JSON.stringify(this)
        return atob(str)
    }

    Parse(lic: string) {
        let str = btoa(lic)
        let obj = JSON.parse(str)

        this.product = obj.product
        this.domain = obj.domain
        this.machine_id = obj.machine_id
        this.expire_at = obj.expire_at
        this.signature = obj.signature
    }

    Serialize() {
        let str = ""
        str += "p:" + this.product + "\n"
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

    Expired() {
        return dayjs().isAfter(dayjs(this.expire_at))
    }

    Validate() {
        let ds = this.domain.split(",")
        for (let i = 0; i < ds.length; i++) {
            if (ds[i] == location.hostname) {
                return true
            }
        }
        return false
    }
}

