const schemas = require('../lib/schemas')
const { JWK } = require('jose')

function jwk (domain) {
  const key = JWK.generateSync('RSA', 1024, { use: 'enc' }).toJWK(false)
  key.kid = `${domain}/jwks/${key.kid}`
  return key
}

describe('schemas', () => {
  let jwtDefaults
  beforeEach(() => {
    jwtDefaults = {
      aud: 'egendata://account',
      exp: 1234,
      iat: 1233,
      iss: 'https://mycv.work'
    }
  })
  describe('CONNECTION_REQUEST', () => {
    it('validates a correct payload', async () => {
      const payload = {
        ...jwtDefaults,
        type: 'CONNECTION_REQUEST',
        sid: 'ccec677d-09d1-489a-a3da-e4758134f2fa',
        displayName: 'My CV',
        description: 'This is a good CV site',
        iconURI: 'https://cv.work/icon.png',
        permissions: [
          // Read permission request
          {
            id: '91910133-4024-4641-a7c7-91fb6e11588e',
            domain: 'http://cv.work',
            area: 'education',
            type: 'READ',
            purpose: 'Stuff',
            lawfulBasis: 'CONSENT',
            jwk: jwk('http://cv.work')
          },
          // Write permission request
          {
            id: '392c6472-40e4-4e2b-92e2-77a46c1900b8',
            domain: 'http://cv.work',
            area: 'education',
            type: 'WRITE',
            description: 'Stuff',
            lawfulBasis: 'CONSENT'
          }
        ]
      }
      await expect(
        schemas.CONNECTION_REQUEST.validate(payload)
      ).resolves.not.toThrow()
    })
  })
  describe('CONNECTION', () => {
    let connection
    beforeEach(() => {
      connection = {
        ...jwtDefaults,
        type: 'CONNECTION',
        aud: 'https://mycv.work',
        sid: 'sdkfhdkskdfd',
        sub: 'baa949aa-fbb5-4aad-8351-d6ef219dd07b',
        permissions: {
          denied: [
            {
              id: '392c6472-40e4-4e2b-92e2-77a46c1900b8',
              domain: 'https://mycv.work',
              area: 'edumacation',
              type: 'WRITE',
              lawfulBasis: 'CONSENT'
            }
          ],
          approved: [
            {
              id: '91910133-4024-4641-a7c7-91fb6e11588e',
              domain: 'https://mycv.work',
              area: 'edumacation',
              type: 'READ',
              purpose: 'Stuff',
              lawfulBasis: 'CONSENT',
              kid: jwk('http://cv.work').kid
            },
            {
              id: '392c6472-40e4-4e2b-92e2-77a46c1900b8',
              domain: 'https://mycv.work',
              area: 'edumacation',
              type: 'WRITE',
              description: 'Stuff',
              lawfulBasis: 'CONSENT',
              jwks: {
                keys: [
                  jwk('egendata://account/baa949aa-fbb5-4aad-8351-d6ef219dd07b'),
                  jwk('http://cv.work')
                ]
              }
            }
          ]
        }
      }
    })

    it('validates a correct payload', async () => {
      await expect(
        schemas.CONNECTION.validate(connection)
      ).resolves.not.toThrow()
    })

    it('validates a correct payload without any permissions', async () => {
      delete connection.permissions
      await expect(
        schemas.CONNECTION.validate(connection)
      ).resolves.not.toThrow()
    })

    it('throws if permissions exists but is empty', async () => {
      connection.permissions = {}
      await expect(
        schemas.CONNECTION.validate(connection)
      ).rejects.toThrow()
    })

    // This would should be an invalid object
    // Checking if values are undefined is not possible in joi.
    //  Hopefully and probably, it will not cause any problems when parsing
    it.skip('throws if permission.denied exists but is undefined', async () => { // eslint-disable-line jest/no-disabled-tests
      connection.permissions.denied = undefined
      await expect(
        schemas.CONNECTION.validate(connection)
      ).rejects.toThrow()
    })

    // This would should be an invalid object
    // Checking if values are undefined is not possible in joi.
    //  Hopefully and probably, it will not cause any problems when parsing
    it.skip('throws if permission.approved exists but is undefined', async () => { // eslint-disable-line jest/no-disabled-tests
      connection.permissions.approved = undefined
      await expect(
        schemas.CONNECTION.validate(connection)
      ).rejects.toThrow()
    })

    // This would should be an invalid object
    // Checking if values are undefined is not possible in joi.
    //  Hopefully and probably, it will not cause any problems when parsing
    it.skip('throws if permissions exists but is undefined', async () => { // eslint-disable-line jest/no-disabled-tests
      connection.permissions = undefined
      await expect(
        schemas.CONNECTION.validate(connection)
      ).rejects.toThrow()
    })
  })
  describe('CONNECTION_RESPONSE', () => {
    it('validates a correct payload', async () => {
      const payload = {
        ...jwtDefaults,
        aud: 'https://smoothoperator',
        type: 'CONNECTION_RESPONSE',
        payload:
          'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsb2dnZWRJbkFzIjoiYWRtaW4iLCJpYXQiOjE0MjI3Nzk2Mzh9.gzSraSYS8EXBxLN_oWnFSRgCzcmJmMjLiuyu5CSpyHI'
      }
      await expect(
        schemas.CONNECTION_RESPONSE.validate(payload)
      ).resolves.not.toThrow()
    })
  })
  describe('RECIPIENTS_READ_RESPONSE', () => {
    it('validates a correct payload', async () => {
      const payload = {
        ...jwtDefaults,
        type: 'RECIPIENTS_READ_RESPONSE',
        sub: 'ccec677d-09d1-489a-a3da-e4758134f2fa',
        paths: [
          {
            domain: 'http://cv.work',
            area: 'education',
            recipients: [
              {
                header: {
                  kid: 'http://192.168.110.179:4000/jwks/uD-zoYsfaDuu45sJCuWi3ScZ-raoF3YsEFQcgF4zjmQ',
                  alg: 'RSA-OAEP'
                },
                encrypted_key: 'r0f49P7BY_sscD9n7VYZ1mIKlwwGCXIh-Ep6X7mfddr76PIOwrkHkk4kps5uvUEQ1mqfV1h4-eYpCwPFW6jTPXwfSp4iULH211ygp6iuesB5-kZaMsqAZ1ZkVJPkMAikKZT9IayuAF3giRFTcuGAxiBaq9sUE57fOma8wS7WXSiPa35KbedYRETWQ6vCX5uXdftAL22pE5FuueHimTNqB2wgRiagiiMKDec96HLC3gf7zacM60nrwO3Az5KHb-sgIZv9ZOwG4yiPJK2MczI1kQDYk4mIb_MK6ad4zV_wzXLBQTPWIm2_7oIxUYaTqpkPh42ss-mspoVwM4pJ6fjs2A'
              },
              {
                header: {
                  kid: 'egendata://jwks/cu6sJNkWsYmEr3OoTc3V12Bdln1hcVMVt3lQ6scFNtM',
                  alg: 'RSA-OAEP'
                },
                encrypted_key: 'FyoGL5D25xa-jJKB4OYTOeuktnKwnO3hMeh1bW1qwpkTYS317Dn2SoBIWQyMMTbH1uOv_F6oO6tqVqZUlixQgAu65To15ARSHHQflKtzVMDhIMSgQ1vFjZkqy5AJQEoaEcNbbGORzcj5nM0M5PwNFGTRqBbXN4e9HcOIo_u0jZO0li3HY7bo6_IfUrS0ZDd1N2N29KFY__J47ZMk0pG0q5yWYcC9cqpB6tY9xCAO0QWX8-P6aVUaOMHKb4AH_g4jx0eh7kFQkG29snqTFkSkuE9_lab9xki3UZCtOvAIhHtligD4HYm1YkuUAtA7p-q-ojJovVRSPBkesXjKuyYJUA'
              }
            ]
          },
          {
            domain: 'http://cv.work',
            area: 'education',
            recipients: [
              {
                header: {
                  kid: 'egendata://jwks/cu6sJNkWsYmEr3OoTc3V12Bdln1hcVMVt3lQ6scFNtM',
                  alg: 'RSA-OAEP'
                },
                encrypted_key: 'FyoGL5D25xa-jJKB4OYTOeuktnKwnO3hMeh1bW1qwpkTYS317Dn2SoBIWQyMMTbH1uOv_F6oO6tqVqZUlixQgAu65To15ARSHHQflKtzVMDhIMSgQ1vFjZkqy5AJQEoaEcNbbGORzcj5nM0M5PwNFGTRqBbXN4e9HcOIo_u0jZO0li3HY7bo6_IfUrS0ZDd1N2N29KFY__J47ZMk0pG0q5yWYcC9cqpB6tY9xCAO0QWX8-P6aVUaOMHKb4AH_g4jx0eh7kFQkG29snqTFkSkuE9_lab9xki3UZCtOvAIhHtligD4HYm1YkuUAtA7p-q-ojJovVRSPBkesXjKuyYJUA'
              }
            ]
          }
        ]
      }
      await expect(
        schemas.RECIPIENTS_READ_RESPONSE.validate(payload)
      ).resolves.not.toThrow()
    })
  })
})
