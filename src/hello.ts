import {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Handler,
} from 'aws-lambda'

const handler: Handler<APIGatewayProxyEvent, APIGatewayProxyResult> = async (
  _event,
  _context
) => {
  return {
    statusCode: 200,
    body: JSON.stringify({
      msg: 'Hello Netlify Functions',
    }),
  }
}

export { handler }
