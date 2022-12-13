import {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Handler,
} from 'aws-lambda'
import axios from 'axios'
import * as forge from 'node-forge'
import * as querystring from 'querystring'

type CinetPayNotifyBody = {
  cpm_site_id: string
  cpm_trans_id: string
  cpm_trans_date: string
  cpm_amount: string
  cpm_currency: string // XAF | USD
  signature: string
  payment_method: string
  cel_phone_num: string
  cpm_phone_prefixe: string
  cpm_language: string
  cpm_version: string
  cpm_payment_config: string
  cpm_page_action: string
  cpm_custom: string
  cpm_designation: string
  cpm_error_message: string
}

type CinetPayVerificationResponse = {
  code: string
  message: 'SUCCES' | 'PAYMENT_FAILED'
  data: {
    amount: string
    currency: string // XAF | USD
    status: 'REFUSED' | 'ACCEPTED'
    payment_method: string
    description: string
    metadata: string | null
    operator_id: string | null
    payment_date: string
  }
  api_response_id: string
}

const handler: Handler<APIGatewayProxyEvent, APIGatewayProxyResult> = async (
  event,
  _context
) => {
  const method = event.httpMethod

  if (method === 'POST') {
    let body: CinetPayNotifyBody
    if (event.isBase64Encoded && typeof event.body === 'string') {
      const buffer = Buffer.from(event.body, 'base64')
      const rawQueryString = buffer.toString('utf8')

      body = querystring.parse(rawQueryString) as CinetPayNotifyBody
    } else {
      const isValidBody = /^{.*}$/.test(event.body)
      const rawBody = isValidBody ? (event.body as string) : '{}'

      body = JSON.parse(rawBody) as CinetPayNotifyBody
    }

    const plainText =
      body.cpm_site_id +
      body.cpm_trans_id +
      body.cpm_trans_date +
      body.cpm_amount +
      body.cpm_currency +
      body.signature +
      body.payment_method +
      body.cel_phone_num +
      body.cpm_phone_prefixe +
      body.cpm_language +
      body.cpm_version +
      body.cpm_payment_config +
      body.cpm_page_action +
      body.cpm_designation +
      body.cpm_error_message

    const hmac = forge.hmac.create()
    hmac.start('sha256', process.env.CINET_PAY_SECRET_KEY as string)
    hmac.update(plainText)
    const hashText = hmac.digest().toHex()

    if (hashText !== event.headers['x-token']) {
      return {
        statusCode: 401,
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          message: 'Invalid token',
        }),
      }
    }

    try {
      const { data } = await axios.post<CinetPayVerificationResponse>(
        process.env.CINET_PAY_TRANSACTION_CHECK_URL as string,
        {
          apikey: process.env.CINET_PAY_API_KEY,
          site_id: process.env.CINET_PAY_SITE_ID,
          transaction_id: body.cpm_trans_id,
        }
      )

      // TODO: Write your code here
    } catch (e) {
      console.error(e)
      return {
        statusCode: 500,
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          error: e.message,
          message: 'Internal server error',
        }),
      }
    }
  }

  if (method === 'GET') {
    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        message: 'Callback is up and running',
      }),
    }
  }

  return {
    statusCode: 405,
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      message: 'Method not allowed',
    }),
  }
}

export { handler }
