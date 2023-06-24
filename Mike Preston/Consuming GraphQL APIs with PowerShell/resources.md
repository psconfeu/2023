# Consuming GraphQL APIs with PowerShell Resources

## Presentation

The Powerpoint can be found [here](psconf-gql.pptx)

## Sample GraphQL APIs

Here is a comprehensive list of sample and public [GraphQL APIs](https://github.com/graphql-kit/graphql-apis) that you can play with. Throughout the presentation I mostly utilized the [SpaceX API](https://spacex-production.up.railway.app)

## Modules utilized within the presenation

Below are a list of the modules highlighted within the presentation

### PSGraphQL

This module provides an easy wrapper to execute GraphQL Queries and Mutations against any GraphQL API. You can find it listed on the [PowerShell Gallery](https://www.powershellgallery.com/packages/PSGraphQL/1.6.0)

### GraphQL-PowerShell

The [GraphQL-PowerShell Module](https://github.com/graphql-powershell/graphql-powershell) is a pet project that a colleague of mine [Jake Robinson](https://twitter.com/jakerobinson) and [myself](https://twitter.com/mwpreston) have begun development on. At it's core, the module takes a GraphQL schema as an input, introspects the queries, and outputs a dynamic module containing cmdlets that map to all of the queries discovered. It is very much in its' infancy and if you want to help out we'd be happy to accept any commits.

## GraphiQL Application

This nifty applications allows you to perform live queries and mutations against a GraphQL endpoint. Perhaps the best thing about GraphiQL is the ability to easily browse and search through the schema with dymanic documentation to figure out what fields are available within a given type or query. You can find it [here](https://github.com/graphql/graphiql)

## Follow along

To follow along with the code within the presentation, simply open up [graphql.ps1](graphql.ps1) and have fun!

## Thank you!

Thank you so much for attending my session. This was my first PSConf, both attending and presenting. I hope to be at many more in the future. If you have any questions feel free to reach out via [Twitter](https://twitter.com/mwpreston) or [LinkedIn](https://www.linkedin.com/in/mwpreston/)