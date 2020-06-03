const {forwardTo} = require('prisma-binding');
const {hasPermission} = require('../utils');

const Query = {
    items: forwardTo('db'),
    item: forwardTo('db'),
    itemsConnection: forwardTo('db'),
    me(parent, args, ctx, info) {
        // check for user id
        if(!ctx.request.userId) {
            return null;
        } 
        return ctx.db.query.user({
            where: {id: ctx.request.userId},
        }, info);
    },
    async users(parent, args, ctx, info) {
        // check if loggied in
        if(!ctx.request.userId) {
            throw new Error('You must be loggied in!')
        }
        // check to see if user has permissions to query user
        hasPermission(ctx.request.user, ['ADMIN', 'PERMISSIONUPDATE']);
        return ctx.db.query.users({}, info)
    },

    async order(parent, args, ctx, info) {
        if(!ctx.request.userId) {
            throw new Error('You arent logged in!');
        }

        const order = await ctx.db.query.order({
            where: {id: args.id},
        }, info);

        const ownsOrder = order.user.id === ctx.request.userId;
        const hasPermissionToSeeOrder = ctx.request.user.permissions.includes('ADMIN');
        if(!ownsOrder || !hasPermission) {
            throw new Error('You cant see this');
        }

        return order;
    },

    async orders(parent, args, ctx, info) {
        const {userId} = ctx.request;
        if(!userId) {
            throw new Error('You must be signed in!');
        }
        return ctx.db.query.orders({
            where: {
                user: {id: userId}
            }
        }, info)
    }
};

module.exports = Query;
