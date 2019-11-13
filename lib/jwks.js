require('isomorphic-fetch')

async function getKey (kid) {
  try {
    // eslint-disable-next-line no-undef
    const response = await fetch(kid)
    return response.json()
  } catch (error) {
    throw new Error(`No key found for kid: ${kid}`)
  }
}

async function getKeys (kids) {
  const keyMap = {}
  let kid
  try {
    for (kid of kids) {
      // eslint-disable-next-line no-undef
      const response = await fetch(kid)
      const data = await response.json()
      keyMap[data.kid] = data
    }
    return keyMap
  } catch (error) {
    throw new Error(`No key found for kid: ${kid}`)
  }
}

module.exports = { getKey, getKeys }
