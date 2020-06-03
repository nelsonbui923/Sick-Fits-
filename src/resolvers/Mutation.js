const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken');
const { randomBytes } = require('crypto');
const { promisify } = require('util');
const {transport, makeANiceEmail} = require('../mail');
const {hasPermission} = require('../utils');
const stripe = require('../stripe');


const Mutations = {
    async createItem(parent, args, ctx, info) {
        if(!ctx.request.userId) {
            throw new Error('You must be logged in to do that!')
        }

        const item = await ctx.db.mutation.createItem({
            data: {
                user: {
                    connect: {
                        id: ctx.request.userId,
                    }
                },
                ...args,
            },
        }, info);

        return item;
    },
    updateItem(parent, args, ctx, info) {
        // copy the updates
        const updates = {...args};
        // remove id from updates
        delete updates.id;
        return ctx.db.mutation.updateItem({
            data: updates,
            where: {
                id: args.id
            },
        }, info);
    },
    async deleteItem(parent, args, ctx, info) {
        const where = {id: args.id};
        
        const item = await ctx.db.query.item({where}, `{id title user {id}}`);
        
        const ownsItem = item.user.id === ctx.request.userId;
        const hasPermissions = ctx.request.user.permissions.some(permission => ['ADMIN', 'ITEMDELETE'].includes(permission));
        if(!ownsItem && hasPermissions) {
            throw new Error('You dont have permission to do that!')
        }
        
        return ctx.db.mutation.deleteItem({where}, info);

    },

    async signup(parent, args, ctx, info) {
        args.email = args.email.toLowerCase();
        // hash password
        const password = await bcrypt.hash(args.password, 10);
        const user = await ctx.db.mutation.createUser({
            data: {
                ...args,
                password,
                permissions: {set: ['USER']}
            }
        }, info);
        // create jwt token
        const token = jwt.sign({userId: user.id}, process.env.APP_SECRET);
        // set jwt as a cookie on the response
        ctx.response.cookie('token', token, {
            httpOnly: true,
            maxAge: 1000 * 60 * 60 * 24 * 365,
        });
        // return user to brower
        return user;
    },
    
    async signin(parent, {email, password}, ctx, info) {
        // check user with email
        const user = await ctx.db.query.user({ where: {email} });
        if(!user) {
            throw new Error(`No user registered with ${email}`);
        }
        // check pw is correct
        const valid = await bcrypt.compare(password, user.password);
        if(!valid) {
            throw new Error('Invalid Password. Please try again.')
        }
        // generate token for user
        const token = jwt.sign({userId: user.id}, process.env.APP_SECRET);
        // set cookie with token
        ctx.response.cookie('token', token, {
            httpOnly: true,
            maxAge: 1000 * 60 * 60 * 24 * 365,
        })
        return user;
    },

    signout (parent, args, ctx, info) {
        ctx.response.clearCookie('token');
        return {message: 'Goodbye!'};
    },

    async requestReset (parent, args, ctx, info) {
        // check for real user
        const user = await ctx.db.query.user({where: {email: args.email} });
        if(!user) {
            throw new Error(`No such user found.`);
        }
        // set reset token for user
        const randomBytesPromiseified = promisify(randomBytes);
        const resetToken = (await randomBytesPromiseified(20)).toString('hex');
        const resetTokenExpiry = Date.now() + 3600000;
        const res = await ctx.db.mutation.updateUser({
            where: {email: args.email},
            data: {resetToken, resetTokenExpiry}
        });
        // email reset token
        const mailRes = await transport.sendMail({
            from: 'nelson@bui.com',
            to: user.email,
            subject: 'Your password reset token',
            html: makeANiceEmail(`Your Password Reset Link. \n\n <a href="${process.env.FRONTEND_URL}/reset?resetToken${resetToken}">Click here to reset.</a>`)
        });
        return {message: 'Thanks!'}
    },

    async resetPassword(parent, args, ctx, info) {
        // 1. check if the passwords match
        if (args.password !== args.confirmPassword) {
          throw new Error("Yo Passwords don't match!");
        }
        // 2. check if its a legit reset token
        // 3. Check if its expired
        const [user] = await ctx.db.query.users({
          where: {
            resetToken: args.resetToken,
            resetTokenExpiry_gte: Date.now() - 3600000,
          },
        });
        if (!user) {
          throw new Error('This token is either invalid or expired!');
        }
        // 4. Hash their new password
        const password = await bcrypt.hash(args.password, 10);
        // 5. Save the new password to the user and remove old resetToken fields
        const updatedUser = await ctx.db.mutation.updateUser({
          where: { email: user.email },
          data: {
            password,
            resetToken: null,
            resetTokenExpiry: null,
          },
        });
        // 6. Generate JWT
        const token = jwt.sign({ userId: updatedUser.id }, process.env.APP_SECRET);
        // 7. Set the JWT cookie
        ctx.response.cookie('token', token, {
          httpOnly: true,
          maxAge: 1000 * 60 * 60 * 24 * 365,
        });
        // 8. return the new user
        return updatedUser;
      },

      async updatePermissions(parent, args, ctx, info) {
        if(!ctx.request.userId) {
            throw new Error('You must be logged in!')
        }
        
        const currentUser = await ctx.db.query.user({ where: {id: ctx.request.userId }}, info)

        hasPermission(currentUser, ['ADMIN', 'PERMISSIONUPDATE']);
        return ctx.db.mutation.updateUser({
            data: {
                permissions: {
                    set: args.permissions,
                },
            },
            where: {
                id: args.userId,
            },
        }, info)
      },

      async addToCart(parent, args, ctx, info) {
        //  make sure users are signed in
        const {userId} = ctx.request;
        if(!userId) {
            throw new Error('You must be signed in.');
        }
        // query users current cart
        const [existingCartItem] =  await ctx.db.query.cartItems({
            where: {
                user: {id: userId}, 
                item: {id: args.id},
            }
        });
        // check if that item is already in the cart
        if(existingCartItem) {
            console.log('this item is already in your cart!');
            return ctx.db.mutation.updateCartItem({
                where: {id: existingCartItem.id},
                data: {quantity: existingCartItem.quantity + 1},
            }, info)
        }
        // if its not, create a fresh cart item for that user
        return ctx.db.mutation.createCartItem({
            data: {
                user: {
                    connect: {id: userId},
                },
                item: {
                    connect: {id: args.id},
                }
            }
        }, info)
      },
    
      async removeFromCart(parent, args, ctx, info) {
        // find cart item
        const cartItem = await ctx.db.query.cartItem({
            where: {
                id: args.id,
            }
        }, `{ id, user {id}}`)
        if(!cartItem) throw new Error('No Cart Item Found!');
        // make sure they own the item
        if(cartItem.user.id !== ctx.request.userId) {
            throw new Error('This is not your item!');
        }
        // delete item
        return ctx.db.mutation.deleteCartItem({
            where: { id: args.id },
        }, info);
      },

      async createOrder(parent, args, ctx, info) {
        // query current user
        const { userId } = ctx.request;
        if(!userId) throw new Error('You must be signed in to complete this order.');
        const user = await ctx.db.query.user({ where: { id: userId } }, 
            `{
                id 
                name 
                email 
                cart { 
                    id 
                    quantity 
                    item { 
                    title price id description image largeImage}
                }}`)
        // recalc the total for the price
        const amount = user.cart.reduce(
            (tally, cartItem) => tally + cartItem.item.price * cartItem.quantity, 0);
        
        // console. log(`going to charge ${amount}`)
        // create stripe charge
        const charge = await stripe.charges.create({
            amount,
            currency: 'USD',
            source: args.token,
        })
        // convert cartitems to orderitems
        const orderItems = user.cart.map(cartItem => {
            const orderItem = {
                ...cartItem.item,
                quantity: cartItem.quantity,
                user: { connect: { id: userId } },
            };
            delete orderItem.id;
            return orderItem;
        })
        // create order
        const order = await ctx.db.mutation.createOrder({
            data: {
                total: charge.amount,
                charge: charge.id,
                items: { create: orderItems },
                user: { connect: { id: userId } },
            }
        })
        // clear user cart
        const cartItemIds = user.cart.map(cartItem => cartItem.id);
        await ctx.db.mutation.deleteManyCartItems({ 
            where: {
                id_in: cartItemIds,
            }  
        })
        // return order to client
        return order;
      }

};

module.exports = Mutations;
